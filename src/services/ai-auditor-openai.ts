/**
 * AI Auditor using OpenAI API
 */

import OpenAI from 'openai';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { createChildLogger } from '../lib/logger.js';
import { KnowledgeBaseService } from './knowledge-base.js';
import type { ParsedContract, VulnerabilityFinding, VulnCategory, Severity } from '../types/index.js';

const logger = createChildLogger('ai-auditor-openai');

const AUDIT_SYSTEM_PROMPT = `You are a senior smart contract security auditor. Analyze the provided Solidity code for vulnerabilities.

For each vulnerability found, output JSON in this exact format:
{
  "findings": [
    {
      "category": "REENTRANCY|ACCESS_CONTROL|ARITHMETIC|LOGIC_ERROR|ORACLE_MANIPULATION|TOKEN_HANDLING|EXTERNAL_INTERACTION|DATA_VALIDATION|GAS_ISSUE|PROTOCOL_SPECIFIC",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "Brief title",
      "description": "Detailed description of the vulnerability",
      "filePath": "path/to/file.sol",
      "functionName": "vulnerableFunction",
      "startLine": 45,
      "endLine": 60,
      "codeSnippet": "relevant code",
      "remediation": "How to fix",
      "confidence": 0.85
    }
  ]
}

Think like an attacker. Look for:
- Reentrancy (state changes after external calls)
- Access control issues (missing modifiers, wrong checks)
- Arithmetic issues (overflow, precision loss, division by zero)
- Oracle manipulation (price manipulation, stale data)
- Logic errors (incorrect calculations, edge cases)
- Flash loan attack vectors
- Price manipulation
- Sandwich attacks
- Front-running vulnerabilities

Be thorough but avoid false positives. Only report issues you're confident about.
If no vulnerabilities found, return: {"findings": []}`;

export class AiAuditorOpenAI {
  private kbService: KnowledgeBaseService;
  private openai: OpenAI;

  constructor(apiKey: string) {
    this.kbService = new KnowledgeBaseService();
    this.openai = new OpenAI({ apiKey });
    logger.info('OpenAI AI auditor initialized');
  }

  async analyze(contracts: ParsedContract[], project: any): Promise<VulnerabilityFinding[]> {
    logger.info({ contractCount: contracts.length }, 'Starting OpenAI-based AI analysis');

    const allFindings: VulnerabilityFinding[] = [];

    // Process contracts in batches (3 contracts per batch to stay within token limits)
    const batches = this.batchContracts(contracts, 3);

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

    logger.info({ totalFindings: allFindings.length }, 'OpenAI AI analysis completed');
    return allFindings;
  }

  private async analyzeBatch(contracts: ParsedContract[], project: any): Promise<VulnerabilityFinding[]> {
    try {
      // Get similar vulnerabilities from knowledge base for context
      const sampleCode = contracts[0]?.sourceCode.substring(0, 1000) || '';
      const similarVulns = await this.kbService.semanticSearch(sampleCode, 5);
      
      // Build context
      const context = this.buildContext(similarVulns, project);

      // Build the user message with contract code
      const contractsContent = contracts.map(c => 
        `### File: ${c.filePath}\n\`\`\`solidity\n${c.sourceCode}\n\`\`\``
      ).join('\n\n');

      const userMessage = `${context}

Analyze these smart contracts for security vulnerabilities. Return findings as JSON.

Protocol type: ${project.protocolType || 'Unknown'}

${contractsContent}`;

      // Call OpenAI API
      const response = await this.openai.chat.completions.create({
        model: 'gpt-4o',
        messages: [
          { role: 'system', content: AUDIT_SYSTEM_PROMPT },
          { role: 'user', content: userMessage }
        ],
        temperature: 0.1,
        max_tokens: 4096,
        response_format: { type: 'json_object' }
      });

      const content = response.choices[0]?.message?.content || '{"findings": []}';
      
      // Parse JSON from response
      const findings = this.parseResponse(content, contracts);
      return findings;

    } catch (error: any) {
      logger.error({ error: error.message }, 'OpenAI analysis failed');
      
      if (error.message?.includes('API key')) {
        logger.error('Invalid OpenAI API key');
      }
      
      return [];
    }
  }

  private buildContext(similarVulns: any[], project: any): string {
    let context = '## Similar Historical Vulnerabilities\n\n';
    
    if (similarVulns.length > 0) {
      similarVulns.forEach((v, i) => {
        context += `${i + 1}. [${v.severity}] ${v.title}\n`;
        context += `   Category: ${v.category}\n`;
        context += `   ${v.description?.substring(0, 200)}...\n\n`;
      });
    } else {
      context += 'No similar vulnerabilities found in knowledge base.\n\n';
    }

    return context;
  }

  private parseResponse(response: string, contracts: ParsedContract[]): VulnerabilityFinding[] {
    try {
      const data = JSON.parse(response);
      const findings = data.findings || [];

      return findings.map((f: any, index: number) => ({
        id: `openai-${Date.now()}-${index}`,
        category: this.validateCategory(f.category),
        severity: this.validateSeverity(f.severity),
        title: f.title || 'Untitled Finding',
        description: f.description || '',
        location: {
          filePath: f.filePath || contracts[0]?.filePath || 'unknown',
          contractName: f.contractName,
          functionName: f.functionName,
          startLine: f.startLine || 0,
          endLine: f.endLine || f.startLine || 0,
        },
        detectionMethod: 'AI_INFERENCE' as const,
        confidence: typeof f.confidence === 'number' ? f.confidence : 0.7,
        codeSnippet: f.codeSnippet,
        remediation: f.remediation,
        references: f.references || [],
      }));

    } catch (error) {
      logger.error({ error }, 'Failed to parse OpenAI response');
      return [];
    }
  }

  private batchContracts(contracts: ParsedContract[], batchSize: number): ParsedContract[][] {
    const batches: ParsedContract[][] = [];
    for (let i = 0; i < contracts.length; i += batchSize) {
      batches.push(contracts.slice(i, i + batchSize));
    }
    return batches;
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
}
