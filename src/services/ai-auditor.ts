import Anthropic from '@anthropic-ai/sdk';
import { config } from '../lib/config.js';
import { createChildLogger } from '../lib/logger.js';
import { KnowledgeBaseService } from './knowledge-base.js';
import type { ParsedContract, VulnerabilityFinding, VulnCategory, Severity } from '../types/index.js';

const logger = createChildLogger('ai-auditor');

const SYSTEM_PROMPT = `You are a senior smart contract security auditor with extensive experience in finding vulnerabilities in Solidity code. You have deep knowledge of:
- Common vulnerability patterns (reentrancy, access control, arithmetic issues, etc.)
- DeFi-specific attacks (oracle manipulation, flash loan attacks, MEV, etc.)
- Best practices for secure smart contract development
- Historical exploits and how they were executed

Your task is to analyze smart contracts and identify potential security vulnerabilities.

For each vulnerability you find, you MUST provide:
1. Category (one of: ACCESS_CONTROL, REENTRANCY, ARITHMETIC, LOGIC_ERROR, ORACLE_MANIPULATION, TOKEN_HANDLING, EXTERNAL_INTERACTION, DATA_VALIDATION, GAS_ISSUE, PROTOCOL_SPECIFIC)
2. Severity (one of: CRITICAL, HIGH, MEDIUM, LOW, INFO)
3. Title (concise description)
4. Description (detailed explanation)
5. Location (file path, function name, line numbers if possible)
6. Remediation (how to fix it)

Think like an attacker. Consider edge cases, cross-function interactions, and economic attacks.

Respond in JSON format with an array of vulnerabilities.`;

const AUDIT_PROMPT = `Analyze the following smart contract(s) for security vulnerabilities.

Contract Information:
- Protocol Type: {{PROTOCOL_TYPE}}
- Dependencies: {{DEPENDENCIES}}

Similar historical vulnerabilities found in the knowledge base:
{{SIMILAR_VULNS}}

Source Code:
{{SOURCE_CODE}}

Instructions:
1. Carefully read and understand the contract logic
2. Identify the trust assumptions and invariants
3. Look for violations of common security patterns
4. Consider attack vectors specific to this protocol type
5. Pay special attention to areas similar to the historical vulnerabilities listed above

Return your findings as a JSON array:
[
  {
    "category": "REENTRANCY",
    "severity": "HIGH",
    "title": "Cross-function Reentrancy in withdraw()",
    "description": "Detailed description...",
    "filePath": "contracts/Vault.sol",
    "functionName": "withdraw",
    "startLine": 45,
    "endLine": 60,
    "codeSnippet": "relevant code...",
    "remediation": "How to fix...",
    "confidence": 0.85
  }
]

If no vulnerabilities are found, return an empty array: []`;

export class AiAuditor {
  private client: Anthropic | null = null;
  private kbService: KnowledgeBaseService;

  constructor() {
    if (config.anthropicApiKey) {
      this.client = new Anthropic({
        apiKey: config.anthropicApiKey,
      });
    }
    this.kbService = new KnowledgeBaseService();
  }

  async analyze(contracts: ParsedContract[], project: any): Promise<VulnerabilityFinding[]> {
    if (!this.client) {
      logger.warn('AI auditor skipped: no API key configured');
      return [];
    }

    logger.info({ contractCount: contracts.length }, 'Starting AI analysis');

    const allFindings: VulnerabilityFinding[] = [];

    // Process contracts in batches to stay within token limits
    const batches = this.batchContracts(contracts);

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      logger.info({ batch: i + 1, total: batches.length }, 'Processing batch');

      try {
        const findings = await this.analyzeBatch(batch, project);
        allFindings.push(...findings);
      } catch (error) {
        logger.error({ error, batch: i + 1 }, 'Failed to analyze batch');
      }
    }

    return allFindings;
  }

  private async analyzeBatch(contracts: ParsedContract[], project: any): Promise<VulnerabilityFinding[]> {
    // Get relevant vulnerabilities from knowledge base
    const sourceCode = contracts.map(c => c.sourceCode).join('\n\n');
    const similarVulns = await this.kbService.semanticSearch(
      sourceCode.substring(0, 2000),
      10
    );

    // Build the prompt
    const prompt = AUDIT_PROMPT
      .replace('{{PROTOCOL_TYPE}}', project.protocolType || 'Unknown')
      .replace('{{DEPENDENCIES}}', JSON.stringify(project.dependencies || []))
      .replace('{{SIMILAR_VULNS}}', this.formatSimilarVulns(similarVulns))
      .replace('{{SOURCE_CODE}}', this.formatSourceCode(contracts));

    try {
      const response = await this.client!.messages.create({
        model: config.defaultAiModel,
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        messages: [
          { role: 'user', content: prompt },
        ],
      });

      const content = response.content[0];
      if (content.type !== 'text') {
        return [];
      }

      // Extract JSON from response
      const jsonMatch = content.text.match(/\[[\s\S]*\]/);
      if (!jsonMatch) {
        logger.warn('No JSON array found in AI response');
        return [];
      }

      const rawFindings = JSON.parse(jsonMatch[0]);
      return this.convertFindings(rawFindings);

    } catch (error) {
      logger.error({ error }, 'AI analysis failed');
      throw error;
    }
  }

  private batchContracts(contracts: ParsedContract[]): ParsedContract[][] {
    const batches: ParsedContract[][] = [];
    let currentBatch: ParsedContract[] = [];
    let currentSize = 0;
    const maxBatchSize = 100000; // ~100k characters per batch

    for (const contract of contracts) {
      const size = contract.sourceCode.length;

      if (currentSize + size > maxBatchSize && currentBatch.length > 0) {
        batches.push(currentBatch);
        currentBatch = [];
        currentSize = 0;
      }

      currentBatch.push(contract);
      currentSize += size;
    }

    if (currentBatch.length > 0) {
      batches.push(currentBatch);
    }

    return batches;
  }

  private formatSourceCode(contracts: ParsedContract[]): string {
    return contracts.map(c => 
      `// File: ${c.filePath}\n${c.sourceCode}`
    ).join('\n\n' + '='.repeat(80) + '\n\n');
  }

  private formatSimilarVulns(vulns: any[]): string {
    if (!vulns || vulns.length === 0) {
      return 'No similar vulnerabilities found in knowledge base.';
    }

    return vulns.map((v, i) => 
      `${i + 1}. [${v.severity}] ${v.title}\n   Category: ${v.category}\n   Description: ${v.description?.substring(0, 200)}...`
    ).join('\n\n');
  }

  private convertFindings(rawFindings: any[]): VulnerabilityFinding[] {
    return rawFindings.map((f, index) => ({
      id: `ai-${Date.now()}-${index}`,
      category: this.validateCategory(f.category),
      severity: this.validateSeverity(f.severity),
      title: f.title || 'Untitled Finding',
      description: f.description || '',
      location: {
        filePath: f.filePath || 'unknown',
        contractName: f.contractName,
        functionName: f.functionName,
        startLine: f.startLine || 0,
        endLine: f.endLine || f.startLine || 0,
      },
      detectionMethod: 'AI_INFERENCE',
      confidence: typeof f.confidence === 'number' ? f.confidence : 0.7,
      codeSnippet: f.codeSnippet,
      remediation: f.remediation,
      references: f.references || [],
    }));
  }

  private validateCategory(category: string): VulnCategory {
    const validCategories: VulnCategory[] = [
      'ACCESS_CONTROL', 'REENTRANCY', 'ARITHMETIC', 'LOGIC_ERROR',
      'ORACLE_MANIPULATION', 'TOKEN_HANDLING', 'EXTERNAL_INTERACTION',
      'DATA_VALIDATION', 'GAS_ISSUE', 'PROTOCOL_SPECIFIC',
    ];
    return validCategories.includes(category as VulnCategory) 
      ? category as VulnCategory 
      : 'LOGIC_ERROR';
  }

  private validateSeverity(severity: string): Severity {
    const validSeverities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    return validSeverities.includes(severity as Severity)
      ? severity as Severity
      : 'MEDIUM';
  }

  async analyzeFunction(
    functionCode: string,
    context: {
      contractName: string;
      filePath: string;
      protocolType?: string;
    }
  ): Promise<VulnerabilityFinding[]> {
    if (!this.client) {
      return [];
    }

    const prompt = `Analyze this specific function for vulnerabilities:

Contract: ${context.contractName}
File: ${context.filePath}
Protocol Type: ${context.protocolType || 'Unknown'}

Function Code:
\`\`\`solidity
${functionCode}
\`\`\`

Return findings as JSON array.`;

    try {
      const response = await this.client.messages.create({
        model: config.defaultAiModel,
        max_tokens: 2048,
        system: SYSTEM_PROMPT,
        messages: [
          { role: 'user', content: prompt },
        ],
      });

      const content = response.content[0];
      if (content.type !== 'text') {
        return [];
      }

      const jsonMatch = content.text.match(/\[[\s\S]*\]/);
      if (!jsonMatch) {
        return [];
      }

      return this.convertFindings(JSON.parse(jsonMatch[0]));

    } catch (error) {
      logger.error({ error }, 'Function analysis failed');
      return [];
    }
  }
}
