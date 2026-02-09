import { execSync } from 'child_process';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import Anthropic from '@anthropic-ai/sdk';
import { config } from '../lib/config.js';
import { createChildLogger } from '../lib/logger.js';
import { KnowledgeBaseService } from './knowledge-base.js';
import type { ParsedContract, PoCResult, VulnCategory } from '../types/index.js';

const logger = createChildLogger('poc-generator');

const POC_SYSTEM_PROMPT = `You are an expert smart contract security researcher specializing in writing Proof of Concept (PoC) exploits. Your PoCs are:
- Written in Foundry/Forge test format
- Executable and verifiable
- Well-documented with comments
- Complete with setup and assertions

You write clean, professional exploit code that demonstrates vulnerabilities clearly.`;

const POC_TEMPLATE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC for {{TITLE}}
 * @notice Severity: {{SEVERITY}}
 * @dev 
 * Attack Vector: {{DESCRIPTION}}
 * Impact: {{IMPACT}}
 */
contract PoCTest is Test {
    // ==================== Constants ====================
    {{CONSTANTS}}
    
    // ==================== State Variables ====================
    {{STATE_VARS}}
    
    // ==================== Setup ====================
    function setUp() public {
        {{SETUP}}
    }
    
    // ==================== Attack ====================
    function test_attack() public {
        // Record initial state
        {{INITIAL_STATE}}
        
        // Execute attack
        {{ATTACK_STEPS}}
        
        // Verify attack success
        {{ASSERTIONS}}
        
        // Log results
        {{LOGGING}}
    }
    
    {{HELPER_CONTRACTS}}
}`;

export class PocGenerator {
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

  async generate(
    vulnerability: any,
    contracts: ParsedContract[],
    project: any
  ): Promise<PoCResult> {
    logger.info({ vulnId: vulnerability.id, title: vulnerability.title }, 'Generating PoC');

    try {
      // Get similar PoCs from knowledge base
      const similarPocs = await this.kbService.findSimilarPocs(
        vulnerability.category,
        vulnerability.title
      );

      // Generate PoC using AI
      const pocCode = await this.generatePocCode(vulnerability, contracts, similarPocs);

      if (!pocCode) {
        return {
          success: false,
          code: '',
          setupCommands: [],
          executionCommand: '',
          verified: false,
          error: 'Failed to generate PoC code',
        };
      }

      // Try to verify the PoC
      const verificationResult = await this.verifyPoc(pocCode, project);

      return {
        success: true,
        code: pocCode,
        setupCommands: this.getSetupCommands(project),
        executionCommand: 'forge test --match-test test_attack -vvvv',
        verified: verificationResult.success,
        executionLog: verificationResult.log,
        estimatedLoss: await this.estimateLoss(vulnerability, contracts),
      };

    } catch (error) {
      logger.error({ error, vulnId: vulnerability.id }, 'PoC generation failed');
      return {
        success: false,
        code: '',
        setupCommands: [],
        executionCommand: '',
        verified: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async generatePocCode(
    vulnerability: any,
    contracts: ParsedContract[],
    similarPocs: any[]
  ): Promise<string | null> {
    if (!this.client) {
      // Return a template-based PoC if no AI available
      return this.generateTemplatePoc(vulnerability);
    }

    const prompt = `Generate a Foundry/Forge PoC for the following vulnerability:

## Vulnerability Details
- Title: ${vulnerability.title}
- Category: ${vulnerability.category}
- Severity: ${vulnerability.severity}
- Description: ${vulnerability.description}
- File: ${vulnerability.filePath}
- Function: ${vulnerability.functionName || 'N/A'}
- Lines: ${vulnerability.startLine}-${vulnerability.endLine}

## Vulnerable Code
\`\`\`solidity
${vulnerability.codeSnippet || 'Code not available'}
\`\`\`

## Contract Context
${contracts.slice(0, 3).map(c => `
### ${c.name} (${c.filePath})
\`\`\`solidity
${c.sourceCode.substring(0, 3000)}${c.sourceCode.length > 3000 ? '\n// ... truncated' : ''}
\`\`\`
`).join('\n')}

## Similar PoCs for Reference
${similarPocs.slice(0, 2).map((p, i) => `
### Example ${i + 1}: ${p.title}
\`\`\`solidity
${p.pocCode?.substring(0, 1500) || 'No code available'}
\`\`\`
`).join('\n')}

## Requirements
1. Write a complete Foundry test that demonstrates the vulnerability
2. Include all necessary imports and setup
3. Add clear comments explaining each step
4. Include assertions that verify the attack succeeded
5. If mainnet forking is needed, use vm.createSelectFork

Return ONLY the Solidity code, no explanations.`;

    try {
      const response = await this.client.messages.create({
        model: config.defaultAiModel,
        max_tokens: 4096,
        system: POC_SYSTEM_PROMPT,
        messages: [
          { role: 'user', content: prompt },
        ],
      });

      const content = response.content[0];
      if (content.type !== 'text') {
        return null;
      }

      // Extract code from response
      const codeMatch = content.text.match(/```solidity\n([\s\S]*?)```/) ||
                       content.text.match(/```\n([\s\S]*?)```/);
      
      if (codeMatch) {
        return codeMatch[1].trim();
      }

      // If no code blocks, assume the entire response is code
      if (content.text.includes('pragma solidity')) {
        return content.text.trim();
      }

      return null;

    } catch (error) {
      logger.error({ error }, 'AI PoC generation failed');
      return this.generateTemplatePoc(vulnerability);
    }
  }

  private generateTemplatePoc(vulnerability: any): string {
    const category = vulnerability.category as VulnCategory;
    
    // Category-specific templates
    const templates: Partial<Record<VulnCategory, string>> = {
      REENTRANCY: this.getReentrancyTemplate(vulnerability),
      ACCESS_CONTROL: this.getAccessControlTemplate(vulnerability),
      ARITHMETIC: this.getArithmeticTemplate(vulnerability),
    };

    return templates[category] || this.getGenericTemplate(vulnerability);
  }

  private getReentrancyTemplate(vuln: any): string {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC for ${vuln.title}
 * @notice Severity: ${vuln.severity}
 */
contract ReentrancyPoCTest is Test {
    // Target contract interface
    // TODO: Replace with actual contract interface
    address target;
    AttackContract attacker;
    
    function setUp() public {
        // TODO: Deploy or fork contracts
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK_NUMBER);
        
        attacker = new AttackContract(target);
        vm.deal(address(attacker), 10 ether);
    }
    
    function test_reentrancy_attack() public {
        uint256 initialBalance = address(attacker).balance;
        
        // Execute attack
        attacker.attack();
        
        uint256 finalBalance = address(attacker).balance;
        assertGt(finalBalance, initialBalance, "Attack should profit");
        
        console.log("Profit:", finalBalance - initialBalance);
    }
}

contract AttackContract {
    address public target;
    uint256 public attackCount;
    
    constructor(address _target) {
        target = _target;
    }
    
    function attack() external payable {
        // TODO: Call vulnerable function
        // ITarget(target).vulnerableFunction{value: msg.value}();
    }
    
    receive() external payable {
        if (attackCount < 10) {
            attackCount++;
            // TODO: Re-enter vulnerable function
            // ITarget(target).vulnerableFunction();
        }
    }
}`;
  }

  private getAccessControlTemplate(vuln: any): string {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC for ${vuln.title}
 * @notice Severity: ${vuln.severity}
 */
contract AccessControlPoCTest is Test {
    address target;
    address attacker = address(0xBAD);
    
    function setUp() public {
        // TODO: Deploy or fork contracts
        vm.deal(attacker, 10 ether);
    }
    
    function test_access_control_bypass() public {
        vm.startPrank(attacker);
        
        // TODO: Call function that should be restricted
        // Verify unauthorized access succeeded
        
        vm.stopPrank();
    }
}`;
  }

  private getArithmeticTemplate(vuln: any): string {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC for ${vuln.title}
 * @notice Severity: ${vuln.severity}
 */
contract ArithmeticPoCTest is Test {
    address target;
    
    function setUp() public {
        // TODO: Deploy or fork contracts
    }
    
    function test_arithmetic_issue() public {
        // TODO: Demonstrate arithmetic vulnerability
        // e.g., overflow, precision loss, rounding error
        
        // uint256 result = ITarget(target).calculate(type(uint256).max);
        // assertEq(result, expectedValue, "Arithmetic issue demonstrated");
    }
}`;
  }

  private getGenericTemplate(vuln: any): string {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC for ${vuln.title}
 * @notice Severity: ${vuln.severity}
 * @dev ${vuln.description}
 */
contract PoCTest is Test {
    // TODO: Add contract references
    
    function setUp() public {
        // TODO: Setup test environment
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK_NUMBER);
    }
    
    function test_vulnerability() public {
        // TODO: Implement attack steps
        
        // 1. Setup initial state
        
        // 2. Execute attack
        
        // 3. Verify attack success
    }
}`;
  }

  private async verifyPoc(
    code: string,
    project: any
  ): Promise<{ success: boolean; log?: string }> {
    try {
      // Create temp directory for PoC
      const tmpDir = path.join(os.tmpdir(), `poc-${Date.now()}`);
      await fs.mkdir(tmpDir, { recursive: true });

      // Initialize foundry project
      execSync('forge init --no-git', { cwd: tmpDir, stdio: 'pipe' });

      // Write PoC file
      const pocPath = path.join(tmpDir, 'test', 'PoC.t.sol');
      await fs.writeFile(pocPath, code);

      // Try to compile
      try {
        execSync('forge build', { cwd: tmpDir, stdio: 'pipe', timeout: 60000 });
      } catch (error) {
        logger.warn('PoC compilation failed');
        return { success: false, log: 'Compilation failed' };
      }

      // Try to run (might fail if it needs mainnet fork)
      try {
        const result = execSync(
          'forge test --match-test test_ -vvv 2>&1 || true',
          { cwd: tmpDir, encoding: 'utf-8', timeout: 120000 }
        );
        
        const success = result.includes('[PASS]');
        return { success, log: result.substring(0, 5000) };
      } catch (error) {
        return { success: false, log: 'Execution failed (may need RPC URL)' };
      }

    } catch (error) {
      logger.error({ error }, 'PoC verification failed');
      return { success: false };
    }
  }

  private getSetupCommands(project: any): string[] {
    return [
      '# Setup Foundry project',
      'forge init poc-test',
      'cd poc-test',
      '',
      '# If forking mainnet:',
      'export ETH_RPC_URL="your-rpc-url"',
      '',
      '# Copy PoC to test directory',
      'cp PoC.t.sol test/',
      '',
      '# Install dependencies if needed',
      'forge install',
    ];
  }

  private async estimateLoss(vulnerability: any, contracts: ParsedContract[]): Promise<string | undefined> {
    // Simple heuristic based on severity
    const estimates: Record<string, string> = {
      CRITICAL: 'Potential total loss of funds',
      HIGH: 'Significant financial impact possible',
      MEDIUM: 'Limited financial impact',
      LOW: 'Minimal direct financial impact',
    };

    return estimates[vulnerability.severity];
  }
}
