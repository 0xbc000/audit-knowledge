import { execSync, exec } from 'child_process';
import { promisify } from 'util';
import { createChildLogger } from '../lib/logger.js';
import type { VulnerabilityFinding, Severity, VulnCategory, DetectionMethod } from '../types/index.js';

const execAsync = promisify(exec);
const logger = createChildLogger('static-analyzer');

// Slither detector to severity mapping
const SLITHER_SEVERITY_MAP: Record<string, Severity> = {
  'High': 'HIGH',
  'Medium': 'MEDIUM',
  'Low': 'LOW',
  'Informational': 'INFO',
  'Optimization': 'INFO',
};

// Slither detector to category mapping
const SLITHER_CATEGORY_MAP: Record<string, VulnCategory> = {
  'reentrancy-eth': 'REENTRANCY',
  'reentrancy-no-eth': 'REENTRANCY',
  'reentrancy-benign': 'REENTRANCY',
  'reentrancy-events': 'REENTRANCY',
  'reentrancy-unlimited-gas': 'REENTRANCY',
  'uninitialized-state': 'DATA_VALIDATION',
  'uninitialized-storage': 'DATA_VALIDATION',
  'uninitialized-local': 'DATA_VALIDATION',
  'arbitrary-send-eth': 'ACCESS_CONTROL',
  'arbitrary-send-erc20': 'ACCESS_CONTROL',
  'controlled-delegatecall': 'ACCESS_CONTROL',
  'controlled-array-length': 'DATA_VALIDATION',
  'suicidal': 'ACCESS_CONTROL',
  'unprotected-upgrade': 'ACCESS_CONTROL',
  'shadowing-state': 'LOGIC_ERROR',
  'shadowing-local': 'LOGIC_ERROR',
  'tx-origin': 'ACCESS_CONTROL',
  'unchecked-transfer': 'TOKEN_HANDLING',
  'unchecked-lowlevel': 'EXTERNAL_INTERACTION',
  'unchecked-send': 'EXTERNAL_INTERACTION',
  'divide-before-multiply': 'ARITHMETIC',
  'integer-division': 'ARITHMETIC',
  'incorrect-equality': 'LOGIC_ERROR',
  'locked-ether': 'LOGIC_ERROR',
  'mapping-deletion': 'DATA_VALIDATION',
  'array-by-reference': 'DATA_VALIDATION',
  'timestamp': 'LOGIC_ERROR',
  'weak-prng': 'LOGIC_ERROR',
  'calls-loop': 'GAS_ISSUE',
  'costly-loop': 'GAS_ISSUE',
  'dead-code': 'GAS_ISSUE',
};

export class StaticAnalyzer {
  async analyze(projectPath: string): Promise<VulnerabilityFinding[]> {
    logger.info({ projectPath }, 'Running static analysis');

    const findings: VulnerabilityFinding[] = [];

    // Run Slither if available
    const slitherFindings = await this.runSlither(projectPath);
    findings.push(...slitherFindings);

    // Run custom pattern matchers
    const patternFindings = await this.runPatternMatchers(projectPath);
    findings.push(...patternFindings);

    logger.info({ findingsCount: findings.length }, 'Static analysis completed');
    return findings;
  }

  private async runSlither(projectPath: string): Promise<VulnerabilityFinding[]> {
    const findings: VulnerabilityFinding[] = [];

    try {
      // Check if slither is installed
      execSync('which slither', { stdio: 'pipe' });

      logger.info('Running Slither analysis');

      const { stdout, stderr } = await execAsync(
        `slither "${projectPath}" --json - 2>/dev/null || true`,
        {
          timeout: 300000,
          maxBuffer: 50 * 1024 * 1024,
        }
      );

      if (!stdout.trim()) {
        logger.warn('Slither produced no output');
        return findings;
      }

      const result = JSON.parse(stdout);

      if (result.success === false) {
        logger.warn({ error: result.error }, 'Slither analysis failed');
        return findings;
      }

      if (result.results?.detectors) {
        for (const detector of result.results.detectors) {
          findings.push(this.convertSlitherFinding(detector));
        }
      }

      logger.info({ slitherFindings: findings.length }, 'Slither analysis completed');
    } catch (error) {
      logger.warn({ error }, 'Slither analysis skipped or failed');
    }

    return findings;
  }

  private convertSlitherFinding(detector: any): VulnerabilityFinding {
    const elements = detector.elements || [];
    const firstElement = elements[0] || {};
    const sourceMapping = firstElement.source_mapping || {};

    return {
      id: `slither-${detector.check}-${sourceMapping.start || Date.now()}`,
      category: SLITHER_CATEGORY_MAP[detector.check] || 'LOGIC_ERROR',
      severity: SLITHER_SEVERITY_MAP[detector.impact] || 'INFO',
      title: detector.check.replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
      description: detector.description || detector.markdown || 'No description available',
      location: {
        filePath: sourceMapping.filename || 'unknown',
        contractName: firstElement.type_specific_fields?.parent?.name,
        functionName: firstElement.name,
        startLine: sourceMapping.lines?.[0] || 0,
        endLine: sourceMapping.lines?.[sourceMapping.lines.length - 1] || 0,
      },
      detectionMethod: 'STATIC_ANALYSIS' as DetectionMethod,
      confidence: detector.confidence === 'High' ? 0.9 : detector.confidence === 'Medium' ? 0.7 : 0.5,
      codeSnippet: firstElement.source_mapping?.content,
      remediation: this.getRemediationForCheck(detector.check),
      references: [detector.wiki_url].filter(Boolean),
    };
  }

  private async runPatternMatchers(projectPath: string): Promise<VulnerabilityFinding[]> {
    const findings: VulnerabilityFinding[] = [];
    const { glob } = await import('glob');
    const { promises: fs } = await import('fs');

    // Find all Solidity files
    const files = await glob('**/*.sol', {
      cwd: projectPath,
      ignore: ['**/node_modules/**', '**/lib/**', '**/*.t.sol'],
      absolute: true,
    });

    for (const filePath of files) {
      const content = await fs.readFile(filePath, 'utf-8');
      const relativePath = filePath.replace(projectPath + '/', '');
      const lines = content.split('\n');

      // Pattern 1: tx.origin usage
      const txOriginMatches = this.findPattern(content, /tx\.origin/g);
      for (const match of txOriginMatches) {
        findings.push({
          id: `pattern-tx-origin-${relativePath}-${match.line}`,
          category: 'ACCESS_CONTROL',
          severity: 'MEDIUM',
          title: 'Use of tx.origin for Authorization',
          description: 'Using tx.origin for authorization can make the contract vulnerable to phishing attacks. An attacker can trick a user into calling a malicious contract that then calls your contract.',
          location: {
            filePath: relativePath,
            startLine: match.line,
            endLine: match.line,
          },
          detectionMethod: 'PATTERN_MATCH',
          confidence: 0.8,
          codeSnippet: lines[match.line - 1],
          remediation: 'Use msg.sender instead of tx.origin for authorization checks.',
          references: ['https://swcregistry.io/docs/SWC-115'],
        });
      }

      // Pattern 2: Unchecked external calls
      const callMatches = this.findPattern(content, /\.call\{/g);
      for (const match of callMatches) {
        const lineContent = lines[match.line - 1];
        if (!lineContent.includes('require') && !lineContent.includes('if')) {
          findings.push({
            id: `pattern-unchecked-call-${relativePath}-${match.line}`,
            category: 'EXTERNAL_INTERACTION',
            severity: 'MEDIUM',
            title: 'Unchecked External Call',
            description: 'The return value of an external call is not checked. This can lead to silent failures.',
            location: {
              filePath: relativePath,
              startLine: match.line,
              endLine: match.line,
            },
            detectionMethod: 'PATTERN_MATCH',
            confidence: 0.6,
            codeSnippet: lineContent,
            remediation: 'Always check the return value of external calls.',
            references: ['https://swcregistry.io/docs/SWC-104'],
          });
        }
      }

      // Pattern 3: Potential reentrancy (state change after external call)
      const reentrancyIssues = this.detectPotentialReentrancy(content, relativePath);
      findings.push(...reentrancyIssues);

      // Pattern 4: Dangerous selfdestruct
      const selfdestructMatches = this.findPattern(content, /selfdestruct\s*\(/g);
      for (const match of selfdestructMatches) {
        findings.push({
          id: `pattern-selfdestruct-${relativePath}-${match.line}`,
          category: 'ACCESS_CONTROL',
          severity: 'HIGH',
          title: 'Use of selfdestruct',
          description: 'The contract uses selfdestruct which can be dangerous if not properly protected.',
          location: {
            filePath: relativePath,
            startLine: match.line,
            endLine: match.line,
          },
          detectionMethod: 'PATTERN_MATCH',
          confidence: 0.7,
          codeSnippet: lines[match.line - 1],
          remediation: 'Ensure selfdestruct is properly protected with access controls.',
          references: ['https://swcregistry.io/docs/SWC-106'],
        });
      }

      // Pattern 5: Block timestamp dependence
      const timestampMatches = this.findPattern(content, /block\.timestamp/g);
      for (const match of timestampMatches) {
        const lineContent = lines[match.line - 1];
        if (lineContent.includes('require') || lineContent.includes('if')) {
          findings.push({
            id: `pattern-timestamp-${relativePath}-${match.line}`,
            category: 'LOGIC_ERROR',
            severity: 'LOW',
            title: 'Block Timestamp Dependence',
            description: 'The contract relies on block.timestamp for critical logic. Miners can manipulate timestamps within certain bounds.',
            location: {
              filePath: relativePath,
              startLine: match.line,
              endLine: match.line,
            },
            detectionMethod: 'PATTERN_MATCH',
            confidence: 0.5,
            codeSnippet: lineContent,
            remediation: 'Be aware that block.timestamp can be manipulated by miners. Avoid using it for time-sensitive operations.',
            references: ['https://swcregistry.io/docs/SWC-116'],
          });
        }
      }
    }

    return findings;
  }

  private findPattern(content: string, pattern: RegExp): Array<{ line: number; match: string }> {
    const results: Array<{ line: number; match: string }> = [];
    const lines = content.split('\n');
    
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      results.push({ line: lineNumber, match: match[0] });
    }

    return results;
  }

  private detectPotentialReentrancy(content: string, filePath: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];
    const lines = content.split('\n');

    // Simple heuristic: look for external calls followed by state changes
    const functionRegex = /function\s+(\w+)[^{]*\{([^}]*)\}/gs;
    let funcMatch;

    while ((funcMatch = functionRegex.exec(content)) !== null) {
      const funcBody = funcMatch[2];
      const funcName = funcMatch[1];
      
      // Check if function has both external call and state change
      const hasExternalCall = /\.call\{|\.transfer\(|\.send\(/.test(funcBody);
      const hasStateChange = /\w+\s*[+\-*/]?=\s*/.test(funcBody);

      if (hasExternalCall && hasStateChange) {
        const callIndex = funcBody.search(/\.call\{|\.transfer\(|\.send\(/);
        const stateChangeIndex = funcBody.search(/\w+\s*[+\-*/]?=\s*/);

        // If state change appears to be after external call
        if (stateChangeIndex > callIndex) {
          const funcStartLine = content.substring(0, funcMatch.index).split('\n').length;
          
          findings.push({
            id: `pattern-reentrancy-${filePath}-${funcStartLine}`,
            category: 'REENTRANCY',
            severity: 'HIGH',
            title: 'Potential Reentrancy Vulnerability',
            description: `Function ${funcName} appears to have a state change after an external call, which may be vulnerable to reentrancy attacks.`,
            location: {
              filePath,
              functionName: funcName,
              startLine: funcStartLine,
              endLine: funcStartLine + funcBody.split('\n').length,
            },
            detectionMethod: 'PATTERN_MATCH',
            confidence: 0.6,
            remediation: 'Use the Checks-Effects-Interactions pattern. Update state variables before making external calls, or use a reentrancy guard.',
            references: ['https://swcregistry.io/docs/SWC-107'],
          });
        }
      }
    }

    return findings;
  }

  private getRemediationForCheck(check: string): string {
    const remediations: Record<string, string> = {
      'reentrancy-eth': 'Use the Checks-Effects-Interactions pattern or add a reentrancy guard.',
      'reentrancy-no-eth': 'Use the Checks-Effects-Interactions pattern or add a reentrancy guard.',
      'uninitialized-state': 'Initialize all state variables in the constructor.',
      'arbitrary-send-eth': 'Add proper access controls to functions that send ETH.',
      'controlled-delegatecall': 'Avoid using user-controlled addresses in delegatecall.',
      'suicidal': 'Add proper access controls to selfdestruct.',
      'tx-origin': 'Use msg.sender instead of tx.origin for authorization.',
      'unchecked-transfer': 'Always check the return value of token transfers.',
      'divide-before-multiply': 'Perform multiplication before division to avoid precision loss.',
    };

    return remediations[check] || 'Review the code and apply appropriate fixes.';
  }
}
