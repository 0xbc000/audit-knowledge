/**
 * AI Auditor Pro - Multi-Phase Deep Analysis
 * 
 * Mimics experienced auditor workflow:
 * Phase 1: Protocol Understanding
 * Phase 2: Architecture Mapping
 * Phase 3: Invariant Identification
 * Phase 4: Deep Logic Analysis
 * Phase 5: Cross-Contract Flow Analysis
 * 
 * Enhanced 2026-02-04: Dynamic vulnerability knowledge loading
 */

import OpenAI from 'openai';
import { promises as fs } from 'fs';
import * as path from 'path';
import { createChildLogger } from '../lib/logger.js';
import { KnowledgeBaseService } from './knowledge-base.js';
import { vulnerabilityLoader, type LoadedKnowledge } from './vulnerability-loader.js';
import {
  EXPERT_AUDITOR_SYSTEM_PROMPT,
  PHASE1_PROTOCOL_UNDERSTANDING,
  PHASE2_ARCHITECTURE_MAPPING,
  PHASE3_INVARIANT_IDENTIFICATION,
  buildPhase4Prompt,
  buildPhase5Prompt,
  INVARIANT_TEMPLATES,
  ATTACK_VECTOR_CHECKLIST
} from './prompts/auditor-prompts.js';
import type { ParsedContract, VulnerabilityFinding, VulnCategory, Severity } from '../types/index.js';

const logger = createChildLogger('ai-auditor-pro');

// Phase 1: Protocol Understanding
const PHASE1_PROMPT = `You are a senior smart contract security auditor starting a new audit engagement.

Your task is to understand this protocol by analyzing the provided code and documentation.

Output a JSON object with:
{
  "protocolType": "DEX|LENDING|PERPETUALS|VAULT|STAKING|OTHER",
  "summary": "2-3 sentence description of what this protocol does",
  "coreContracts": ["list of most important contract names"],
  "entryPoints": ["main user-facing functions"],
  "valueFlows": ["how value/tokens move through the system"],
  "actors": ["different roles: users, keepers, admins, etc"],
  "criticalOperations": ["operations that move funds or change critical state"],
  "externalDependencies": ["oracles, other protocols, etc"]
}

Focus on understanding the BUSINESS LOGIC, not just code patterns.`;

// Phase 2: Architecture Mapping
const PHASE2_PROMPT = `You are mapping the architecture of a smart contract protocol.

Based on the contracts provided, create a detailed architecture analysis:

{
  "contractRelationships": [
    {"from": "ContractA", "to": "ContractB", "type": "calls|inherits|delegates", "functions": ["func1", "func2"]}
  ],
  "stateVariables": [
    {"contract": "Name", "variable": "varName", "type": "type", "purpose": "what it tracks", "modifiedBy": ["functions"]}
  ],
  "accessControl": [
    {"contract": "Name", "role": "roleName", "capabilities": ["what they can do"]}
  ],
  "upgradeability": "proxy pattern used if any",
  "criticalPaths": [
    {"name": "deposit flow", "steps": ["step1", "step2"], "risks": ["potential issues"]}
  ]
}`;

// Phase 3: Invariant Identification (Enhanced for Expert Auditor Thinking)
const PHASE3_PROMPT = `You are a senior smart contract auditor identifying protocol invariants.

INVARIANTS are conditions that must ALWAYS hold true. When they break, bad things happen.

## HOW TO THINK ABOUT INVARIANTS

### 1. ACCOUNTING INVARIANTS
Ask: "What mathematical relationships must always hold?"
Examples:
- totalSupply == sum of all balances (ERC20)
- totalAssets >= totalLiabilities (lending)
- sum of LP tokens == pool liquidity value
- user debt <= user collateral * LTV

Look for: Storage variables that represent the same thing counted different ways

### 2. STATE MACHINE INVARIANTS  
Ask: "What states can this contract be in? What transitions are valid?"
Examples:
- Proposal: Draft → Active → Executed (can't skip)
- Loan: Open → Liquidated | Repaid (not both)
- User: !registered → registered (one-way)

Look for: Enum states, boolean flags, lifecycle variables

### 3. ACCESS CONTROL INVARIANTS
Ask: "Who should NEVER be able to do X?"
Examples:
- Non-owner can NEVER change critical params
- User A can NEVER access User B's funds
- Paused protocol can NEVER accept deposits

Look for: modifier patterns, require statements checking msg.sender

### 4. ECONOMIC INVARIANTS
Ask: "What economic assumptions does this protocol make?"
Examples:
- Collateral value >= borrow value (lending)
- LP share value monotonically increases (no negative yield)
- Fee recipient receives exactly fee% of transactions
- Flash loans are repaid within same transaction

Look for: Value flows, fee calculations, token transfers

### 5. TEMPORAL INVARIANTS
Ask: "What timing assumptions exist?"
Examples:
- Timelock delay >= minDelay
- Oracle data updated within maxStaleness
- Withdrawal available after lockPeriod
- Interest accrues per block, not retroactively

Look for: block.timestamp comparisons, delay variables

### 6. CROSS-CONTRACT INVARIANTS
Ask: "What must be true across multiple contracts?"
Examples:
- Proxy implementation matches expected interface
- Oracle contract returns valid price range
- Vault balance == sum of all strategy balances

## OUTPUT FORMAT

{
  "accountingInvariants": [
    {
      "invariant": "precise mathematical statement",
      "contracts": ["ContractA", "ContractB"],
      "variables": ["totalSupply", "balances mapping"],
      "checkMethod": "how to verify this holds",
      "violationImpact": "CRITICAL|HIGH|MEDIUM - what happens",
      "attackVector": "how an attacker might break this"
    }
  ],
  "stateMachineInvariants": [...],
  "accessInvariants": [...],
  "economicInvariants": [...],
  "temporalInvariants": [...],
  "crossContractInvariants": [...]
}

## KEY INSIGHT
Every bug is an invariant violation. If you identify the RIGHT invariants, you'll find the bugs.

Think: "If I were trying to BREAK this protocol, what assumption would I violate?"`;

// Phase 4: Deep Logic Analysis (Enhanced for Expert Auditor Thinking)
const PHASE4_PROMPT = `You are a senior smart contract auditor performing DEEP LOGIC ANALYSIS.

## YOUR MINDSET
Think like an attacker who has unlimited time and resources. For each line of code, ask:
"How could this be exploited? What edge cases break this?"

## SYSTEMATIC ANALYSIS

### 1. COMPARISON ERRORS (High-value bugs!)
STOP at every comparison. Ask:
- < vs > → Does off-by-one matter? (liquidation thresholds!)
- <= vs >= → Is boundary case handled correctly?
- == vs != → Can equality be gamed? (dust amounts?)

REAL EXAMPLE:
\`\`\`solidity
// BUG: Should be <=, allows underwater positions
if (collateralValue < debtValue) { liquidate(); }
// Attack: Set collateralValue == debtValue, avoid liquidation
\`\`\`

### 2. CALCULATION ERRORS
STOP at every arithmetic operation. Ask:
- Division before multiplication? (precision loss!)
- Intermediate overflow? (even with SafeMath!)
- Rounding direction? (attacker benefits from wrong direction!)
- Order of operations? (a*b/c vs a/c*b)

REAL EXAMPLE:
\`\`\`solidity
// BUG: Division first loses precision
uint256 fee = amount / 100 * feeRate;  // WRONG
uint256 fee = amount * feeRate / 100;  // CORRECT
\`\`\`

### 3. STATE TRANSITION ERRORS
STOP at every state change. Ask:
- Is this BEFORE or AFTER external call? (reentrancy!)
- Are ALL related variables updated? (inconsistent state!)
- What if this reverts AFTER partial update?

REAL EXAMPLE:
\`\`\`solidity
// BUG: State updated after external call
function withdraw(uint256 amount) {
  payable(msg.sender).transfer(amount);  // External call
  balances[msg.sender] -= amount;  // Too late!
}
\`\`\`

### 4. BOUNDARY CONDITIONS
STOP at every input/output. Ask:
- What if amount = 0? (division by zero? no-op that changes state?)
- What if amount = type(uint256).max? (overflow? DoS?)
- What if array is empty? (index out of bounds?)
- What if this is the FIRST call? (uninitialized state?)
- What if this is the LAST item? (deletion issues?)

REAL EXAMPLE:
\`\`\`solidity
// BUG: Division by zero when totalSupply is 0
uint256 shares = amount * totalSupply / totalAssets;  // Reverts!
\`\`\`

### 5. TRUST ASSUMPTIONS
STOP at every external input. Ask:
- Can msg.sender be a contract? (callback attacks!)
- Can this address be the zero address? (burns/locks!)
- Can this token be a fee-on-transfer token? (wrong accounting!)
- Can this token be a rebasing token? (balance changes!)
- Can this oracle return stale/manipulated data?

REAL EXAMPLE:
\`\`\`solidity
// BUG: Doesn't account for fee-on-transfer tokens
token.transferFrom(sender, address(this), amount);
balances[sender] += amount;  // Actual received may be less!
\`\`\`

### 6. HIDDEN ASSUMPTIONS
Look for IMPLICIT assumptions:
- "This function is only called after X" → What if called directly?
- "Amount will always be reasonable" → What if dust or max?
- "Price will be in normal range" → What if extreme?
- "User will act rationally" → What if malicious?

## OUTPUT FORMAT

{
  "findings": [
    {
      "category": "COMPARISON|CALCULATION|STATE_TRANSITION|BOUNDARY|TRUST|ASSUMPTION",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "SPECIFIC: e.g., 'Off-by-one in liquidation threshold allows underwater positions'",
      "description": "Clear explanation of the exact bug",
      "location": {"file": "path", "function": "name", "line": 123},
      "codeSnippet": "the exact problematic line(s)",
      "expectedBehavior": "what the developer intended",
      "actualBehavior": "what actually happens", 
      "exploitScenario": "Step 1: ... Step 2: ... Step N: Profit",
      "remediation": "EXACT code fix, not just 'add check'",
      "confidence": 0.9
    }
  ]
}

## CRITICAL RULES
1. Report SPECIFIC bugs, not generic patterns ("missing access control" → WHERE?)
2. Include LINE NUMBERS and EXACT code snippets
3. Write CONCRETE exploit scenarios with steps
4. Provide EXACT remediation code, not vague suggestions
5. If you're not confident, set confidence < 0.7

Only report findings you're reasonably confident are real bugs.`;

// Lending Protocol Specific Patterns (from real audit findings)
const LENDING_PATTERNS = `
## LENDING-SPECIFIC VULNERABILITY PATTERNS

Based on real High/Critical findings from production audits:

1. SILENT PERMIT VALIDATION BYPASS
   - Look for: try-catch blocks around permit() that continue on failure
   - Pattern: try IERC20WithPermit(asset).permit(...) {} catch {}
   - Risk: Unauthorized token operations if user had prior approval

2. BAD DEBT ACCOUNTING ERRORS  
   - Look for: Interest rate updates without corresponding token transfers
   - Pattern: updateInterestRates(amount) called when burning bad debt
   - Risk: Protocol-wide interest rate distortion

3. CONFIGURATION STATE INCONSISTENCY
   - Look for: Setter functions that don't validate cross-parameter invariants
   - Pattern: setBorrowableInIsolation(true) when debtCeiling=0
   - Risk: Failed user transactions, gas loss

4. UNBOUNDED ITERATION DOS
   - Look for: Loops over all reserves/users without gas limits
   - Pattern: for (i=0; i < reservesCount; i++) with 100+ reserves
   - Risk: Liquidation failures, cascading insolvency

5. DUST MANIPULATION ATTACKS
   - Look for: State transitions blocked by small collateral amounts
   - Pattern: if (hasNoCollateralLeft) { burnBadDebt() }
   - Risk: Permanent bad debt accumulation

6. CROSS-CHAIN IMPLEMENTATION DIFFERENCES
   - Look for: WETH/ERC20 assumptions that differ across chains
   - Pattern: transferFrom(msg.sender) without checking chain-specific behavior
   - Risk: Complete function breakage on specific chains (e.g., Arbitrum)

7. INTEREST ACCRUAL RACE CONDITIONS
   - Look for: Balance reads followed by delayed burns/mints
   - Pattern: amount = balanceOf(user); [interest accrues]; burn(amount)
   - Risk: Residual debt after "full" repayment, unexpected liquidations

8. LIBRARY ACCESS CONTROL GAPS
   - Look for: Library functions exposed without caller-side access control
   - Pattern: LiquidationLogic.executeLiquidationCall() with no auth check
   - Risk: Unauthorized liquidations, fund theft
`;

// Vault/Yield Protocol Specific Patterns
const VAULT_PATTERNS = `
## VAULT-SPECIFIC VULNERABILITY PATTERNS

1. SHARE PRICE MANIPULATION (First Depositor Attack)
   - Look for: First depositor can manipulate share price
   - Pattern: shares = amount * totalSupply / totalAssets with totalSupply=0
   - Attack: Deposit 1 wei, donate 10000 tokens, next depositor gets 0 shares
   - Risk: Theft from subsequent depositors

2. DONATION ATTACKS
   - Look for: Direct token transfers that inflate totalAssets
   - Pattern: totalAssets() reads balanceOf(this) without accounting safeguards
   - Attack: Donate tokens to vault, manipulate share price
   - Risk: Share value manipulation, depositor loss

3. WITHDRAWAL QUEUE ISSUES
   - Look for: Unbounded withdrawal requests, no rate limiting
   - Pattern: Anyone can request any amount, processed FIFO
   - Risk: Bank run, liquidity crisis

4. VIRTUAL PRICE MANIPULATION
   - Look for: getPricePerShare() used for lending/borrowing
   - Pattern: Price derived from manipulatable balances
   - Risk: Flash loan manipulation of collateral value

5. STRATEGY MIGRATION ISSUES
   - Look for: Funds moved without proper accounting
   - Pattern: migrate() updates strategy but not totalAssets
   - Risk: Share price jumps, MEV extraction
`;

// Economic Attack Patterns (from economic-attack-vectors.md)
const ECONOMIC_ATTACK_PATTERNS = `
## ECONOMIC ATTACK PATTERNS

1. FLASH LOAN AMPLIFIED ATTACKS
   - Oracle manipulation via spot price
   - Collateral inflation for maximum borrowing
   - Governance voting power amplification

2. SANDWICH ATTACKS
   - Swaps without slippage protection (minAmountOut = 0)
   - Large visible mempool transactions
   - Liquidations without competitive mechanisms

3. FIRST DEPOSITOR/LP ATTACKS
   - Share inflation via donation
   - LP token ratio manipulation
   - Minimum deposit not enforced

4. ARBITRAGE & MEV
   - Oracle lag between market and protocol price
   - Cross-protocol price inconsistencies
   - JIT liquidity for reward capture

5. GRIEFING (DoS for Profit)
   - Dust amounts blocking state transitions
   - Gas griefing via forced expensive operations
   - Spam attacks (cheap to grief, expensive to defend)

6. INTEREST RATE MANIPULATION
   - Utilization rate gaming via large borrow/repay
   - Interest accrual timing attacks (deposit before, withdraw after)
`;

// Privilege Escalation Patterns (from privilege-escalation-patterns.md)
const PRIVILEGE_ESCALATION_PATTERNS = `
## PRIVILEGE ESCALATION PATTERNS

1. DIRECT ACCESS CONTROL BYPASSES
   - Missing onlyOwner/onlyRole on critical functions
   - Modifier logic with fallthrough paths
   - Default admin granted to wrong address

2. DELEGATECALL VULNERABILITIES
   - User-controlled delegatecall target → CRITICAL
   - Storage collision in proxy upgrades
   - Implementation contract self-destruct

3. PROXY/UPGRADE VULNERABILITIES
   - Unprotected initialize() (call multiple times)
   - Upgrade without timelock (instant rug)
   - UUPS _authorizeUpgrade without role check

4. SIGNATURE/PERMIT EXPLOITS
   - Missing nonce → replay attack
   - Missing chainId → cross-chain replay
   - try-catch permit with prior approval

5. GOVERNANCE ATTACKS
   - Flash loan voting power
   - Short voting period + weekend execution
   - Low proposal threshold spam

6. EMERGENCY MECHANISM ABUSE
   - Unprotected pause (DoS entire protocol)
   - No unpause function (permanent brick)
   - Pause blocks withdrawals (funds trapped)
`;

// Cross-Contract Attack Patterns (from cross-contract-attack-patterns.md)
const CROSS_CONTRACT_ATTACK_PATTERNS = `
## CROSS-CONTRACT ATTACK PATTERNS

1. REENTRANCY VARIANTS
   - Classic: State update after external call
   - Read-only: View returns stale state during callback
   - Cross-function: Reenter different function without guard
   - Cross-contract: A → B → A via different path
   - Token callbacks: ERC777/ERC1155 hooks

2. FLASH LOAN ATTACKS
   - Collateral inflation
   - Governance manipulation
   - Oracle price manipulation

3. CALLBACK EXPLOITATION
   - Missing msg.sender verification in callbacks
   - Inconsistent state during callback window
   - Approval-triggered callbacks

4. STATE INCONSISTENCY
   - Partial update before external call
   - Cached value divergence
   - Non-atomic multi-step operations

5. EXTERNAL CALL ISSUES
   - Unchecked return values
   - Fee-on-transfer tokens
   - Rebasing token balance assumptions

6. COMPOSABILITY RISKS
   - Hardcoded external addresses
   - Assuming external protocol invariants
   - Multi-protocol sandwich opportunities
`;

// Phase 5: Cross-Contract Analysis (Enhanced for Expert Auditor Thinking)
const PHASE5_PROMPT = `You are a senior smart contract auditor analyzing CROSS-CONTRACT attack paths.

## REENTRANCY ANALYSIS (Check ALL variants)

### Classic Reentrancy
- State update AFTER external call? → CRITICAL
- Pattern: balances[msg.sender] = 0 after .call()

### Read-Only Reentrancy  
- View functions return inconsistent state during callback
- Pattern: totalSupply updated, but ratio calculation reads old value

### Cross-Function Reentrancy
- Function A has guard, Function B doesn't
- Reenter B during A's callback

### Cross-Contract Reentrancy
- ContractA → ContractB → back to ContractA (different path)

### ERC777/ERC1155 Reentrancy
- Token callbacks (tokensReceived, onERC1155Received)
- Before/after transfer hooks

## FLASH LOAN ATTACK PATHS

Ask: "What can an attacker do with 1B tokens for 1 block?"

1. **Collateral Inflation**
   - Flash borrow → deposit as collateral → borrow max → default

2. **Governance Manipulation**
   - Flash borrow gov tokens → vote → return tokens

3. **Price Oracle Manipulation**
   - Flash swap → distort spot price → execute at bad price → swap back

4. **Liquidity Manipulation**
   - Flash LP → claim rewards → return LP

## CALLBACK EXPLOITATION

### Callback Verification
- Does callback check msg.sender is legitimate pool?
- uniswapV3SwapCallback - MUST verify pool address!

### State During Callback
- What state is visible during callback?
- Can attacker exploit partial state?

## PRIVILEGE ESCALATION PATHS

### Delegatecall Chains
- User-controlled delegatecall target? → CRITICAL
- Can attacker modify storage via delegatecall?

### Temporary Privilege
- Flash loan gives voting power
- Callback gives token balance
- Approval gives spending rights

### Role Bypass
- Library functions without access control
- Timelock bypass via direct calls
- Proxy upgrade without authorization

## COMPOSABILITY RISKS

### External Protocol Dependencies
- What if Chainlink returns stale price?
- What if Uniswap pool is manipulated?
- What if integrated protocol is paused?

### Fee-on-Transfer / Rebasing Tokens
- balance check before/after transfer?
- handles automatic balance changes?

### Sandwich Attack Surfaces
- Large swap without slippage protection?
- Visible mempool transaction sequence?

## ATTACK PATH CONSTRUCTION

For each potential vulnerability, construct the FULL attack:

1. **Setup**: What does attacker need? (tokens, flash loan, specific state)
2. **Trigger**: What transaction(s) execute the attack?
3. **Exploit**: How exactly does the vulnerability manifest?
4. **Profit**: How does attacker extract value?
5. **Cleanup**: How does attacker cover tracks?

## OUTPUT FORMAT

{
  "findings": [
    {
      "category": "REENTRANCY|FLASH_LOAN|CALLBACK|PRIVILEGE_ESCALATION|COMPOSABILITY",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "specific attack description",
      "attackPath": [
        "Step 1: Attacker does X",
        "Step 2: This triggers Y",
        "Step 3: ...",
        "Step N: Attacker profits Z"
      ],
      "contracts": ["ContractA", "ContractB"],
      "functions": ["functionA", "functionB"],
      "rootCause": "why this is possible",
      "codeSnippet": "relevant code",
      "exploitScenario": "detailed attack description",
      "remediation": "how to fix",
      "confidence": 0.9
    }
  ]
}

## KEY INSIGHT
The most severe bugs often span multiple contracts. Single-contract analysis misses them.
Think: "How do these contracts interact? Where are the trust boundaries?"`;

interface ProtocolUnderstanding {
  protocolType: string;
  summary: string;
  coreContracts: string[];
  entryPoints: string[];
  valueFlows: string[];
  actors: string[];
  criticalOperations: string[];
  externalDependencies: string[];
}

interface ArchitectureMap {
  contractRelationships: any[];
  stateVariables: any[];
  accessControl: any[];
  upgradeability: string;
  criticalPaths: any[];
}

interface Invariants {
  accountingInvariants: any[];
  accessInvariants: any[];
  economicInvariants: any[];
  stateInvariants: any[];
  timingInvariants: any[];
}

export class AiAuditorPro {
  private openai: OpenAI;
  private kbService: KnowledgeBaseService;
  private protocolUnderstanding: ProtocolUnderstanding | null = null;
  private architectureMap: ArchitectureMap | null = null;
  private invariants: Invariants | null = null;
  private loadedKnowledge: LoadedKnowledge | null = null;

  constructor(apiKey: string) {
    this.openai = new OpenAI({ apiKey });
    this.kbService = new KnowledgeBaseService();
    logger.info('AI Auditor Pro initialized - Multi-phase deep analysis mode (enhanced 2026-02-04)');
  }

  async analyze(contracts: ParsedContract[], project: any): Promise<VulnerabilityFinding[]> {
    logger.info({ contractCount: contracts.length }, 'Starting Pro AI analysis - 5 phases with dynamic knowledge loading');

    const allFindings: VulnerabilityFinding[] = [];

    try {
      // Phase 1: Understand the protocol
      logger.info('=== Phase 1: Protocol Understanding ===');
      this.protocolUnderstanding = await this.phase1_understandProtocol(contracts, project);
      logger.info({ understanding: this.protocolUnderstanding.summary }, 'Protocol understood');
      
      // Load vulnerability knowledge based on protocol type
      logger.info('=== Loading Vulnerability Knowledge Base ===');
      this.loadedKnowledge = await vulnerabilityLoader.loadForProtocol(
        this.protocolUnderstanding.protocolType
      );
      const kbStats = vulnerabilityLoader.getCacheStats();
      logger.info({ 
        protocolType: this.protocolUnderstanding.protocolType,
        filesLoaded: kbStats.files,
        totalKnowledgeSize: `${Math.round(kbStats.totalSize / 1024)}KB`
      }, 'Vulnerability knowledge loaded');

      // Phase 2: Map architecture
      logger.info('=== Phase 2: Architecture Mapping ===');
      this.architectureMap = await this.phase2_mapArchitecture(contracts);
      logger.info({ relationships: this.architectureMap.contractRelationships.length }, 'Architecture mapped');

      // Phase 3: Identify invariants
      logger.info('=== Phase 3: Invariant Identification ===');
      this.invariants = await this.phase3_identifyInvariants(contracts);
      logger.info({ 
        accounting: this.invariants.accountingInvariants.length,
        access: this.invariants.accessInvariants.length,
        economic: this.invariants.economicInvariants.length
      }, 'Invariants identified');

      // Phase 4: Deep logic analysis on critical contracts
      logger.info('=== Phase 4: Deep Logic Analysis ===');
      const criticalContracts = this.getCriticalContracts(contracts);
      for (const contract of criticalContracts) {
        logger.info({ contract: contract.name }, 'Analyzing critical contract');
        const findings = await this.phase4_deepLogicAnalysis(contract);
        allFindings.push(...findings);
      }

      // Phase 5: Cross-contract analysis
      logger.info('=== Phase 5: Cross-Contract Analysis ===');
      const crossFindings = await this.phase5_crossContractAnalysis(contracts);
      allFindings.push(...crossFindings);

      // Deduplicate and rank findings
      const dedupedFindings = this.deduplicateAndRank(allFindings);

      logger.info({ totalFindings: dedupedFindings.length }, 'Pro AI analysis completed');
      return dedupedFindings;

    } catch (error) {
      logger.error({ error }, 'Pro analysis failed');
      throw error;
    }
  }

  private async phase1_understandProtocol(contracts: ParsedContract[], project: any): Promise<ProtocolUnderstanding> {
    // Get README and docs if available
    const readmeContent = await this.findReadme(project);
    
    // Get contract summaries (first 200 lines of each)
    const contractSummaries = contracts.slice(0, 10).map(c => {
      const lines = c.sourceCode.split('\n').slice(0, 200).join('\n');
      return `// File: ${c.filePath}\n${lines}`;
    }).join('\n\n');

    const response = await this.openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: PHASE1_PROTOCOL_UNDERSTANDING },
        { role: 'user', content: `Analyze this protocol and return your response as JSON.\n\nREADME/Docs:\n${readmeContent}\n\nContract Summaries:\n${contractSummaries}` }
      ],
      temperature: 0.1,
      max_tokens: 3000,
      response_format: { type: 'json_object' }
    });

    const content = response.choices[0]?.message?.content || '{}';
    return JSON.parse(content);
  }

  private async phase2_mapArchitecture(contracts: ParsedContract[]): Promise<ArchitectureMap> {
    // Analyze imports and function calls to understand relationships
    const contractInterfaces = contracts.map(c => {
      // Extract function signatures and imports
      const lines = c.sourceCode.split('\n');
      const imports = lines.filter(l => l.trim().startsWith('import')).join('\n');
      const functions = lines.filter(l => 
        l.includes('function ') && (l.includes('external') || l.includes('public'))
      ).join('\n');
      const stateVars = lines.filter(l => 
        l.match(/^\s*(mapping|uint|int|address|bool|bytes|string)\s*.*\s+(public|private|internal)/) ||
        l.match(/^\s*(public|private|internal)\s+(mapping|uint|int|address|bool|bytes|string)/)
      ).join('\n');
      
      return `// ${c.filePath}\n${imports}\n\n// State:\n${stateVars}\n\n// Functions:\n${functions}`;
    }).join('\n\n---\n\n');

    const response = await this.openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: PHASE2_ARCHITECTURE_MAPPING },
        { role: 'user', content: `Map the architecture and return your response as JSON.\n\n${contractInterfaces}` }
      ],
      temperature: 0.1,
      max_tokens: 4000,
      response_format: { type: 'json_object' }
    });

    const content = response.choices[0]?.message?.content || '{}';
    return JSON.parse(content);
  }

  private async phase3_identifyInvariants(contracts: ParsedContract[]): Promise<Invariants> {
    // Provide context from previous phases
    const protocolType = this.protocolUnderstanding?.protocolType?.toUpperCase() || 'OTHER';
    
    // Get invariant templates for this protocol type
    const templates = (INVARIANT_TEMPLATES as any)[protocolType] || [];
    const templateText = templates.length > 0 
      ? `\n\n## REFERENCE INVARIANTS FOR ${protocolType}\n${templates.map((t: any) => 
          `- ${t.name}: ${t.template} (${t.violationImpact})`
        ).join('\n')}`
      : '';
    
    const context = `
Protocol Type: ${this.protocolUnderstanding?.protocolType}
Summary: ${this.protocolUnderstanding?.summary}
Core Contracts: ${this.protocolUnderstanding?.coreContracts?.join(', ')}
Critical Operations: ${this.protocolUnderstanding?.criticalOperations?.join(', ')}
Value Flows: ${this.protocolUnderstanding?.valueFlows?.join(', ')}

Architecture:
${JSON.stringify(this.architectureMap?.criticalPaths, null, 2)}
${templateText}
`;

    // Get core contract code
    const coreContractCode = contracts
      .filter(c => this.protocolUnderstanding?.coreContracts?.some(
        core => c.filePath.toLowerCase().includes(core.toLowerCase())
      ))
      .slice(0, 5)
      .map(c => `// ${c.filePath}\n${c.sourceCode}`)
      .join('\n\n---\n\n');

    const response = await this.openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: PHASE3_INVARIANT_IDENTIFICATION },
        { role: 'user', content: `Identify invariants and return your response as JSON.\n\n${context}\n\nCore Contract Code:\n${coreContractCode}` }
      ],
      temperature: 0.2,
      max_tokens: 4000,
      response_format: { type: 'json_object' }
    });

    const content = response.choices[0]?.message?.content || '{}';
    return JSON.parse(content);
  }

  private async phase4_deepLogicAnalysis(contract: ParsedContract): Promise<VulnerabilityFinding[]> {
    // Build knowledge base content from dynamically loaded files
    const knowledgeBase = this.buildKnowledgeBaseContent();
    
    // Build the enhanced Phase 4 prompt with loaded knowledge
    const phase4Prompt = buildPhase4Prompt(knowledgeBase);
    
    // Provide rich context for analysis
    const context = `
Protocol Understanding:
- Type: ${this.protocolUnderstanding?.protocolType}
- Summary: ${this.protocolUnderstanding?.summary}
- Critical Operations: ${this.protocolUnderstanding?.criticalOperations?.join(', ')}

Key Invariants:
${this.invariants?.accountingInvariants?.map((i: any) => `- ${i.invariant}`).join('\n') || 'None identified'}
${this.invariants?.economicInvariants?.map((i: any) => `- ${i.invariant}`).join('\n') || ''}

${ATTACK_VECTOR_CHECKLIST}
`;

    // Extract and filter to HIGH-RISK functions only
    const functions = this.extractFunctions(contract.sourceCode);
    const highRiskFunctions = functions.filter(func => this.isHighRiskFunction(func.code));
    
    logger.info({ 
      contract: contract.name, 
      total: functions.length, 
      highRisk: highRiskFunctions.length 
    }, 'Filtering to high-risk functions');

    if (highRiskFunctions.length === 0) {
      return [];
    }

    // Batch high-risk functions together (up to 5 per API call)
    const batches = this.batchFunctions(highRiskFunctions, 5);
    const allFindings: VulnerabilityFinding[] = [];

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      const batchCode = batch.map(f => f.code).join('\n\n// ---\n\n');
      
      logger.info({ batch: i + 1, total: batches.length, functions: batch.length }, 'Analyzing function batch');

      try {
        const response = await this.openai.chat.completions.create({
          model: 'gpt-4o',
          messages: [
            { role: 'system', content: phase4Prompt },
            { role: 'user', content: `
Return your analysis as JSON with a "findings" array.

Context:
${context}

Contract: ${contract.filePath}

Functions to analyze (focus on LOGIC ERRORS, not generic patterns):
\`\`\`solidity
${batchCode}
\`\`\`

REMEMBER:
1. Be SPECIFIC - file names, line numbers, exact code
2. Be CONCRETE - real exploit steps, not possibilities  
3. Check comparison operators (< vs > vs <= vs >=)
4. Check calculation order (division before multiplication?)
5. Check state updates (before or after external calls?)
6. Check edge cases (zero, max, empty, first/last)

Only report findings you're confident are real bugs.
` }
          ],
          temperature: 0.1,
          max_tokens: 4000,
          response_format: { type: 'json_object' }
        });

        const content = response.choices[0]?.message?.content || '{"findings": []}';
        const result = JSON.parse(content);
        
        if (result.findings && result.findings.length > 0) {
          const findings = result.findings.map((f: any, idx: number) => this.toFinding(f, contract, idx));
          allFindings.push(...findings);
        }
      } catch (error) {
        logger.warn({ error, batch: i + 1 }, 'Failed to analyze function batch');
      }
    }

    return allFindings;
  }
  
  /**
   * Build knowledge base content from dynamically loaded vulnerability patterns
   */
  private buildKnowledgeBaseContent(): string {
    if (!this.loadedKnowledge) {
      logger.warn('No loaded knowledge available, using fallback patterns');
      return this.getProtocolSpecificPatterns();
    }
    
    const sections: string[] = [];
    
    // Protocol-specific patterns (truncate to reasonable size)
    if (this.loadedKnowledge.protocolPatterns) {
      const truncated = this.loadedKnowledge.protocolPatterns.substring(0, 8000);
      sections.push(`## PROTOCOL-SPECIFIC VULNERABILITY PATTERNS\n${truncated}`);
    }
    
    // Cross-protocol risks (focus on critical parts)
    if (this.loadedKnowledge.crossProtocolRisks) {
      const truncated = this.loadedKnowledge.crossProtocolRisks.substring(0, 4000);
      sections.push(`## CROSS-PROTOCOL RISKS\n${truncated}`);
    }
    
    // Economic risks
    if (this.loadedKnowledge.economicRisks) {
      const truncated = this.loadedKnowledge.economicRisks.substring(0, 4000);
      sections.push(`## ECONOMIC ATTACK VECTORS\n${truncated}`);
    }
    
    return sections.join('\n\n---\n\n');
  }
  
  /**
   * Build knowledge specifically for cross-contract analysis
   */
  private buildCrossContractKnowledge(): string {
    if (!this.loadedKnowledge) {
      logger.warn('No loaded knowledge available for cross-contract analysis');
      return CROSS_CONTRACT_ATTACK_PATTERNS;
    }
    
    const sections: string[] = [];
    
    // Cross-protocol risks are most relevant for cross-contract
    if (this.loadedKnowledge.crossProtocolRisks) {
      sections.push(this.loadedKnowledge.crossProtocolRisks.substring(0, 6000));
    }
    
    // Economic risks often involve cross-contract attacks
    if (this.loadedKnowledge.economicRisks) {
      sections.push(this.loadedKnowledge.economicRisks.substring(0, 4000));
    }
    
    // Include audit techniques if available
    if (this.loadedKnowledge.auditingTechniques) {
      // Extract just the cross-contract relevant parts
      const crossContractSection = this.loadedKnowledge.auditingTechniques
        .split('\n')
        .filter(line => 
          line.toLowerCase().includes('cross') ||
          line.toLowerCase().includes('reentr') ||
          line.toLowerCase().includes('callback') ||
          line.toLowerCase().includes('flash')
        )
        .slice(0, 50)
        .join('\n');
      
      if (crossContractSection) {
        sections.push(`## CROSS-CONTRACT ATTACK TECHNIQUES\n${crossContractSection}`);
      }
    }
    
    return sections.length > 0 
      ? sections.join('\n\n---\n\n')
      : CROSS_CONTRACT_ATTACK_PATTERNS;
  }

  private isHighRiskFunction(code: string): boolean {
    const lower = code.toLowerCase();
    
    // Skip view/pure functions and getters
    if (lower.includes('view') && !lower.includes('nonreentrant')) return false;
    if (lower.includes('pure')) return false;
    if (code.length < 100) return false; // Too small
    
    // High risk indicators
    const highRiskPatterns = [
      /\.transfer\s*\(/,
      /\.call\s*[({]/,
      /safeTransfer/i,
      /\.send\s*\(/,
      /mint\s*\(/,
      /burn\s*\(/,
      /withdraw/i,
      /deposit/i,
      /swap/i,
      /liquidat/i,
      /borrow/i,
      /repay/i,
      /settle/i,
      /claim/i,
      /stake/i,
      /unstake/i,
      /delegat/i,
      /external\s+/,
      /payable/,
      /\+=|-=|\*=|\/=/,  // Arithmetic assignments
      /if\s*\([^)]*[<>=]/,  // Comparisons in conditions
    ];
    
    return highRiskPatterns.some(pattern => pattern.test(code));
  }

  private batchFunctions(functions: { name: string; code: string }[], batchSize: number): { name: string; code: string }[][] {
    const batches: { name: string; code: string }[][] = [];
    for (let i = 0; i < functions.length; i += batchSize) {
      batches.push(functions.slice(i, i + batchSize));
    }
    return batches;
  }

  private async phase5_crossContractAnalysis(contracts: ParsedContract[]): Promise<VulnerabilityFinding[]> {
    // Build knowledge base content for cross-contract analysis
    const knowledgeBase = this.buildCrossContractKnowledge();
    
    // Build the enhanced Phase 5 prompt
    const phase5Prompt = buildPhase5Prompt(knowledgeBase);
    
    // Analyze critical paths identified earlier
    const criticalPaths = this.architectureMap?.criticalPaths || [];
    
    const context = `
Protocol Understanding:
${JSON.stringify(this.protocolUnderstanding, null, 2)}

Key Invariants to Check:
${this.invariants?.accountingInvariants?.slice(0, 5).map((i: any) => `- ${i.invariant}`).join('\n') || 'None'}
${this.invariants?.economicInvariants?.slice(0, 5).map((i: any) => `- ${i.invariant}`).join('\n') || ''}

Critical Paths:
${JSON.stringify(criticalPaths, null, 2)}
`;

    // Get contracts involved in critical paths
    const relevantContracts = contracts
      .filter(c => criticalPaths.some((path: any) => 
        path.steps?.some((step: string) => 
          c.filePath.toLowerCase().includes(step.toLowerCase()) ||
          c.name.toLowerCase().includes(step.toLowerCase())
        )
      ))
      .slice(0, 8);

    // If no contracts matched critical paths, use the scored critical contracts
    const contractsToAnalyze = relevantContracts.length > 0 
      ? relevantContracts 
      : this.getCriticalContracts(contracts).slice(0, 8);

    const contractCode = contractsToAnalyze
      .map(c => `// ${c.filePath}\n${c.sourceCode}`)
      .join('\n\n---\n\n');

    const response = await this.openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: phase5Prompt },
        { role: 'user', content: `Analyze cross-contract attack paths and return your analysis as JSON with a "findings" array.

${context}

Contracts to analyze:
${contractCode}

Focus on:
1. Reentrancy variants (classic, read-only, cross-function, cross-contract)
2. Flash loan attack paths
3. Callback exploitation
4. Trust boundary violations
5. State inconsistency across contracts

Be specific about which contracts and functions are involved in each attack path.` }
      ],
      temperature: 0.1,
      max_tokens: 4000,
      response_format: { type: 'json_object' }
    });

    const content = response.choices[0]?.message?.content || '{"findings": []}';
    const result = JSON.parse(content);

    return (result.findings || []).map((f: any, idx: number) => 
      this.toFinding(f, relevantContracts[0] || contracts[0], idx, 'CROSS_CONTRACT')
    );
  }

  private getCriticalContracts(contracts: ParsedContract[]): ParsedContract[] {
    // Prioritize contracts based on protocol understanding
    const coreNames = this.protocolUnderstanding?.coreContracts || [];
    const criticalOps = this.protocolUnderstanding?.criticalOperations || [];
    
    // Score contracts by importance
    const scored = contracts.map(c => {
      let score = 0;
      const lower = c.filePath.toLowerCase() + ' ' + c.sourceCode.toLowerCase();
      
      // Core contract names
      for (const name of coreNames) {
        if (lower.includes(name.toLowerCase())) score += 10;
      }
      
      // Critical operations
      for (const op of criticalOps) {
        if (lower.includes(op.toLowerCase())) score += 5;
      }
      
      // Contains value transfers
      if (lower.includes('transfer') || lower.includes('safeTransfer')) score += 3;
      
      // Contains critical state changes
      if (lower.includes('mint') || lower.includes('burn')) score += 3;
      
      // External calls
      if (lower.includes('.call') || lower.includes('delegatecall')) score += 2;
      
      // Size (larger = more logic = more bugs)
      score += Math.min(c.sourceCode.split('\n').length / 100, 5);
      
      // Exclude test/mock contracts
      if (lower.includes('test') || lower.includes('mock')) score -= 20;
      
      return { contract: c, score };
    });

    // Return top 8 critical contracts (optimized for speed)
    return scored
      .sort((a, b) => b.score - a.score)
      .slice(0, 8)
      .map(s => s.contract);
  }

  private extractFunctions(code: string): { name: string; code: string }[] {
    const functions: { name: string; code: string }[] = [];
    const lines = code.split('\n');
    
    let inFunction = false;
    let braceCount = 0;
    let currentFunc = { name: '', code: '' };
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Detect function start
      const funcMatch = line.match(/function\s+(\w+)/);
      if (funcMatch && !inFunction) {
        inFunction = true;
        currentFunc = { name: funcMatch[1], code: '' };
        braceCount = 0;
      }
      
      if (inFunction) {
        currentFunc.code += line + '\n';
        braceCount += (line.match(/{/g) || []).length;
        braceCount -= (line.match(/}/g) || []).length;
        
        if (braceCount === 0 && currentFunc.code.includes('{')) {
          functions.push(currentFunc);
          inFunction = false;
        }
      }
    }
    
    return functions;
  }

  private async findReadme(project: any): Promise<string> {
    // Try to find README in the project
    try {
      const possiblePaths = [
        'README.md', 'readme.md', 'docs/README.md', 
        'SPECIFICATION.md', 'docs/SPECIFICATION.md'
      ];
      
      for (const p of possiblePaths) {
        try {
          // This would need the project path from github ingestion
          // For now, return empty
        } catch {}
      }
    } catch {}
    
    return `Project: ${project.name}\nType: ${project.protocolType || 'Unknown'}`;
  }

  private async getSimilarVulns(code: string): Promise<string> {
    try {
      const similar = await this.kbService.semanticSearch(code.substring(0, 1000), 5);
      return similar.map((v: any) => 
        `- [${v.severity}] ${v.title}: ${v.description?.substring(0, 200)}`
      ).join('\n');
    } catch {
      return 'No similar vulnerabilities found.';
    }
  }

  private toFinding(
    raw: any, 
    contract: ParsedContract, 
    index: number,
    prefix: string = 'PRO'
  ): VulnerabilityFinding {
    const categoryMap: Record<string, VulnCategory> = {
      'LOGIC_ERROR': 'LOGIC_ERROR',
      'CALCULATION': 'ARITHMETIC',
      'COMPARISON': 'LOGIC_ERROR',
      'STATE_TRANSITION': 'LOGIC_ERROR',
      'BOUNDARY': 'DATA_VALIDATION',
      'TRUST': 'ACCESS_CONTROL',
      'REENTRANCY': 'REENTRANCY',
      'ACCESS_CONTROL': 'ACCESS_CONTROL',
      'CROSS_CONTRACT': 'EXTERNAL_INTERACTION'
    };

    return {
      id: `${prefix}-${Date.now()}-${index}`,
      category: categoryMap[raw.category] || 'LOGIC_ERROR',
      severity: this.validateSeverity(raw.severity),
      title: raw.title || 'Untitled Finding',
      description: this.buildDescription(raw),
      location: {
        filePath: raw.location?.file || contract.filePath,
        functionName: raw.location?.function,
        startLine: raw.location?.line || 0,
        endLine: raw.location?.line || 0,
      },
      detectionMethod: 'AI_INFERENCE' as const,
      confidence: typeof raw.confidence === 'number' ? raw.confidence : 0.8,
      codeSnippet: raw.codeSnippet,
      remediation: raw.remediation,
      references: [],
    };
  }

  private buildDescription(raw: any): string {
    let desc = raw.description || '';
    
    if (raw.expectedBehavior) {
      desc += `\n\n**Expected Behavior:** ${raw.expectedBehavior}`;
    }
    if (raw.actualBehavior) {
      desc += `\n\n**Actual Behavior:** ${raw.actualBehavior}`;
    }
    if (raw.exploitScenario) {
      desc += `\n\n**Exploit Scenario:**\n${raw.exploitScenario}`;
    }
    
    return desc;
  }

  private validateSeverity(severity: string): Severity {
    const valid: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    return valid.includes(severity as Severity) ? severity as Severity : 'MEDIUM';
  }

  private getProtocolSpecificPatterns(): string {
    const protocolType = this.protocolUnderstanding?.protocolType?.toUpperCase() || '';
    
    // Base patterns that apply to ALL protocols
    const basePatterns = `
## UNIVERSAL PATTERNS (Check for ALL protocols)

### Access Control
- State-changing functions without modifiers
- Modifier logic with fallthrough paths  
- Unprotected initialize()

### Reentrancy (ALL variants)
- Classic: State update after external call
- Read-only: View returns stale state during callback
- Cross-function: Different function without guard
- Cross-contract: A → B → A different path
- Token callbacks: ERC777/ERC1155

### External Calls
- Unchecked return values on transfers
- Fee-on-transfer token handling
- Rebasing token assumptions
`;

    // Return patterns based on protocol type
    if (protocolType.includes('LENDING') || protocolType.includes('BORROW')) {
      logger.info('Applying LENDING protocol patterns');
      return basePatterns + LENDING_PATTERNS + ECONOMIC_ATTACK_PATTERNS;
    }
    
    if (protocolType.includes('VAULT') || protocolType.includes('YIELD') || protocolType.includes('STAKING')) {
      logger.info('Applying VAULT protocol patterns');
      return basePatterns + VAULT_PATTERNS + ECONOMIC_ATTACK_PATTERNS;
    }
    
    // For DEX, PERPETUALS, etc.
    if (protocolType.includes('DEX') || protocolType.includes('SWAP') || protocolType.includes('AMM')) {
      logger.info('Applying DEX protocol patterns');
      return basePatterns + `
## DEX-SPECIFIC VULNERABILITY PATTERNS

1. PRICE MANIPULATION VIA FLASH LOANS
   - Look for: Spot price calculations without TWAP protection
   - Pattern: price = reserveA / reserveB used directly
   - Attack: Flash swap to move price, exploit, swap back
   
2. SANDWICH ATTACK VECTORS
   - Look for: Large swaps without slippage protection
   - Pattern: minAmountOut = 0 or not enforced
   - Attack: Front-run with same-direction swap, back-run opposite
   
3. LP TOKEN INFLATION ATTACKS
   - Look for: First LP can manipulate token ratio
   - Pattern: No minimum liquidity, no dead shares
   - Attack: First depositor sets bad ratio, others lose
   
4. IMBALANCED POOL ATTACKS
   - Look for: Operations that create arbitrage
   - Pattern: Single-sided liquidity changes
   - Attack: MEV extraction from rebalancing

5. ROUTER APPROVAL EXPLOITS
   - Look for: Infinite approvals to router
   - Pattern: approve(router, type(uint256).max)
   - Risk: Router upgrade or bug drains user tokens
` + ECONOMIC_ATTACK_PATTERNS;
    }
    
    // For perpetuals/derivatives
    if (protocolType.includes('PERPETUAL') || protocolType.includes('DERIVATIVE') || protocolType.includes('OPTION')) {
      logger.info('Applying PERPETUALS protocol patterns');
      return basePatterns + `
## PERPETUALS-SPECIFIC VULNERABILITY PATTERNS

1. FUNDING RATE MANIPULATION
   - Look for: Funding rate based on mark-index spread
   - Pattern: Large position influences funding direction
   - Attack: Open massive position, collect funding, close
   
2. LIQUIDATION MEV
   - Look for: Liquidation bots competing for profit
   - Pattern: First-come-first-serve liquidations
   - Attack: Front-run liquidations, extract keeper profit
   
3. ORACLE DELAY EXPLOITATION
   - Look for: Mark price updates lag market
   - Pattern: Position opened at old mark, market moved
   - Attack: Trade on stale oracle, arbitrage the delay

4. POSITION SIZE LIMITS
   - Look for: Max position size enforced
   - Pattern: Split across addresses to bypass
   - Risk: Single entity controls too much OI
   
5. ADL (Auto-Deleveraging) ISSUES
   - Look for: Profitable positions force-closed
   - Pattern: Ranking system for ADL selection
   - Risk: MEV from knowing ADL order
` + ECONOMIC_ATTACK_PATTERNS;
    }

    // For governance protocols
    if (protocolType.includes('GOVERNANCE') || protocolType.includes('DAO')) {
      logger.info('Applying GOVERNANCE protocol patterns');
      return basePatterns + PRIVILEGE_ESCALATION_PATTERNS + `
## GOVERNANCE-SPECIFIC VULNERABILITY PATTERNS

1. FLASH LOAN VOTING
   - Look for: Voting power from token balance
   - Pattern: No snapshot at proposal creation
   - Attack: Flash borrow tokens, vote, return

2. PROPOSAL SPAM
   - Look for: Low threshold to create proposals
   - Pattern: proposalThreshold < economicCost
   - Attack: Spam proposals to distract/exhaust voters

3. SHORT TIMELOCK EXPLOITATION  
   - Look for: Timelock < community reaction time
   - Pattern: Propose Friday, execute Monday
   - Attack: Pass malicious proposal over weekend

4. VOTE BUYING
   - Look for: No commitment period after voting
   - Pattern: Can transfer tokens after voting
   - Risk: Secondary market for votes
`;
    }
    
    // Default patterns for unknown protocol types
    logger.info({ protocolType }, 'Using general vulnerability patterns');
    return basePatterns + ECONOMIC_ATTACK_PATTERNS + PRIVILEGE_ESCALATION_PATTERNS + CROSS_CONTRACT_ATTACK_PATTERNS;
  }

  private deduplicateAndRank(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
    // Remove duplicates based on location and title similarity
    const seen = new Map<string, VulnerabilityFinding>();
    
    for (const finding of findings) {
      const key = `${finding.location.filePath}:${finding.location.startLine}:${finding.title.substring(0, 30)}`;
      const existing = seen.get(key);
      
      if (!existing || finding.confidence > existing.confidence) {
        seen.set(key, finding);
      }
    }
    
    // Sort by severity then confidence
    const severityOrder: Record<string, number> = {
      'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4
    };
    
    return Array.from(seen.values()).sort((a, b) => {
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return b.confidence - a.confidence;
    });
  }
}
