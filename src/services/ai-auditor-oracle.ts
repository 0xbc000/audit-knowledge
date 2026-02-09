/**
 * AI Auditor using Oracle CLI
 * 
 * Uses Clawdbot's oracle CLI to perform AI analysis
 * No separate API key required - uses existing Claude session
 */

import { execSync } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { createChildLogger } from '../lib/logger.js';
import { KnowledgeBaseService } from './knowledge-base.js';
import type { ParsedContract, VulnerabilityFinding, VulnCategory, Severity } from '../types/index.js';

const logger = createChildLogger('ai-auditor-oracle');

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

If no vulnerabilities found, return: {"findings": []}`;

export class AiAuditorOracle {
  private kbService: KnowledgeBaseService;

  constructor() {
    this.kbService = new KnowledgeBaseService();
  }

  async analyze(contracts: ParsedContract[], project: any): Promise<VulnerabilityFinding[]> {
    logger.info({ contractCount: contracts.length }, 'Starting Oracle-based AI analysis');

    const allFindings: VulnerabilityFinding[] = [];

    // Process contracts in batches
    const batches = this.batchContracts(contracts, 3); // 3 contracts per batch

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

    logger.info({ totalFindings: allFindings.length }, 'Oracle AI analysis completed');
    return allFindings;
  }

  private async analyzeBatch(contracts: ParsedContract[], project: any): Promise<VulnerabilityFinding[]> {
    // Create temp directory for contract files
    const tmpDir = path.join(os.tmpdir(), `sca-oracle-${Date.now()}`);
    await fs.mkdir(tmpDir, { recursive: true });

    try {
      // Write contracts to temp files
      const filePaths: string[] = [];
      for (const contract of contracts) {
        const filePath = path.join(tmpDir, contract.filePath.replace(/\//g, '_'));
        await fs.writeFile(filePath, contract.sourceCode);
        filePaths.push(filePath);
      }

      // Get similar vulnerabilities from knowledge base for context
      const sampleCode = contracts[0]?.sourceCode.substring(0, 1000) || '';
      const similarVulns = await this.kbService.semanticSearch(sampleCode, 5);
      
      // Build context
      const context = this.buildContext(similarVulns, project);

      // Build oracle command
      const prompt = `${context}

Analyze these smart contracts for security vulnerabilities. Return findings as JSON.

Protocol type: ${project.protocolType || 'Unknown'}`;

      // Write prompt to file
      const promptFile = path.join(tmpDir, 'prompt.txt');
      await fs.writeFile(promptFile, prompt);

      // Call oracle CLI
      // Write system prompt to file to avoid shell escaping issues with special characters
      const systemPromptFile = path.join(tmpDir, 'system-prompt.txt');
      await fs.writeFile(systemPromptFile, AUDIT_SYSTEM_PROMPT);
      
      const fileArgs = filePaths.map(f => `-f "${f}"`).join(' ');
      const command = `oracle -sf "${systemPromptFile}" ${fileArgs} < "${promptFile}"`;

      logger.debug({ command }, 'Executing oracle command');

      const result = execSync(command, {
        encoding: 'utf-8',
        timeout: 120000, // 2 minute timeout
        maxBuffer: 10 * 1024 * 1024,
      });

      // Parse JSON from response
      const findings = this.parseOracleResponse(result);
      return findings;

    } catch (error) {
      logger.error({ error }, 'Oracle analysis failed');
      
      // If oracle isn't available, return empty
      if ((error as any)?.message?.includes('command not found')) {
        logger.warn('Oracle CLI not available, skipping AI analysis');
        return [];
      }
      
      throw error;
    } finally {
      // Cleanup
      await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
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

  private parseOracleResponse(response: string): VulnerabilityFinding[] {
    try {
      // Try to extract JSON from the response
      const jsonMatch = response.match(/\{[\s\S]*"findings"[\s\S]*\}/);
      if (!jsonMatch) {
        logger.warn('No JSON found in oracle response');
        return [];
      }

      const data = JSON.parse(jsonMatch[0]);
      const findings = data.findings || [];

      return findings.map((f: any, index: number) => ({
        id: `oracle-${Date.now()}-${index}`,
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
        detectionMethod: 'AI_INFERENCE' as const,
        confidence: typeof f.confidence === 'number' ? f.confidence : 0.7,
        codeSnippet: f.codeSnippet,
        remediation: f.remediation,
        references: f.references || [],
      }));

    } catch (error) {
      logger.error({ error }, 'Failed to parse oracle response');
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

  /**
   * Analyze a single function for deeper inspection
   */
  async analyzeFunction(
    functionCode: string,
    context: { contractName: string; filePath: string; protocolType?: string }
  ): Promise<VulnerabilityFinding[]> {
    const tmpDir = path.join(os.tmpdir(), `sca-func-${Date.now()}`);
    await fs.mkdir(tmpDir, { recursive: true });

    try {
      const codeFile = path.join(tmpDir, 'function.sol');
      await fs.writeFile(codeFile, functionCode);

      const prompt = `Analyze this Solidity function for vulnerabilities:
Contract: ${context.contractName}
File: ${context.filePath}
Protocol Type: ${context.protocolType || 'Unknown'}

Return findings as JSON array.`;

      const promptFile = path.join(tmpDir, 'prompt.txt');
      await fs.writeFile(promptFile, prompt);

      const systemPromptFile = path.join(tmpDir, 'system-prompt.txt');
      await fs.writeFile(systemPromptFile, AUDIT_SYSTEM_PROMPT);

      const result = execSync(
        `oracle -sf "${systemPromptFile}" -f "${codeFile}" < "${promptFile}"`,
        { encoding: 'utf-8', timeout: 60000 }
      );

      return this.parseOracleResponse(result);

    } catch (error) {
      logger.error({ error }, 'Function analysis failed');
      return [];
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}
