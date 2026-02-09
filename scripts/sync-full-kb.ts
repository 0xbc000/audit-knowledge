#!/usr/bin/env tsx
/**
 * Full Knowledge Base Sync
 * 
 * Sources:
 * - DeFiHackLabs (679+ real exploit incidents with PoC)
 * - SmartBugs Curated (academic dataset)
 * - SWC Registry (standard vulnerability classification)
 */

import { PrismaClient } from '@prisma/client';

const db = new PrismaClient();

// Category mapping
const CATEGORY_MAP: Record<string, string> = {
  'access_control': 'ACCESS_CONTROL',
  'arithmetic': 'ARITHMETIC',
  'bad_randomness': 'LOGIC_ERROR',
  'denial_of_service': 'GAS_ISSUE',
  'front_running': 'ACCESS_CONTROL',
  'other': 'LOGIC_ERROR',
  'reentrancy': 'REENTRANCY',
  'short_addresses': 'DATA_VALIDATION',
  'time_manipulation': 'LOGIC_ERROR',
  'unchecked_low_level_calls': 'EXTERNAL_INTERACTION',
  'price manipulation': 'ORACLE_MANIPULATION',
  'flash loan': 'ORACLE_MANIPULATION',
  'oracle': 'ORACLE_MANIPULATION',
  'logic flaw': 'LOGIC_ERROR',
  'incorrect': 'LOGIC_ERROR',
};

const stats = {
  total: 0,
  added: 0,
  updated: 0,
  errors: 0,
};

async function syncDeFiHackLabs() {
  console.log('\n📦 Syncing DeFiHackLabs (679+ real exploits)...\n');
  
  // Fetch the README to parse incidents
  const readmeUrl = 'https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/README.md';
  
  try {
    const response = await fetch(readmeUrl);
    const content = await response.text();
    
    // Parse incidents from README
    // Format: [20260112 MTToken](#20260112-mttoken---incorrect-fee-logic)
    const incidentRegex = /\[(\d{8})\s+([^\]]+)\].*?---\s*([^\)]+)/g;
    const incidents: Array<{ date: string; name: string; category: string }> = [];
    
    let match;
    while ((match = incidentRegex.exec(content)) !== null) {
      incidents.push({
        date: match[1],
        name: match[2].trim(),
        category: match[3].trim().toLowerCase(),
      });
    }
    
    console.log(`   Found ${incidents.length} incidents in README`);
    
    // Process incidents
    for (const incident of incidents.slice(0, 200)) { // Limit to 200 for now
      await upsertEntry({
        source: 'defihacklabs',
        sourceId: `defi-${incident.date}-${incident.name.replace(/\s+/g, '-').toLowerCase()}`,
        sourceUrl: `https://github.com/SunWeb3Sec/DeFiHackLabs`,
        title: `${incident.name} - ${incident.category}`,
        description: `Real exploit incident from ${incident.date}. Attack type: ${incident.category}. Full PoC available in DeFiHackLabs repository.`,
        category: inferCategory(incident.category),
        severity: inferSeverity(incident.category),
        tags: [incident.category.replace(/-/g, ' '), 'real-exploit', 'poc-available'],
        publishedAt: parseDate(incident.date),
      });
    }
    
    console.log(`   ✅ Processed ${Math.min(incidents.length, 200)} DeFiHackLabs entries`);
  } catch (error) {
    console.error('   ❌ Failed to sync DeFiHackLabs:', error);
    stats.errors++;
  }
}

async function syncSmartBugs() {
  console.log('\n📚 Syncing SmartBugs Curated Dataset...\n');
  
  const url = 'https://raw.githubusercontent.com/smartbugs/smartbugs-curated/main/vulnerabilities.json';
  
  try {
    const response = await fetch(url);
    const data = await response.json();
    
    console.log(`   Found ${data.length} contracts in SmartBugs`);
    
    for (const contract of data) {
      for (const vuln of contract.vulnerabilities) {
        await upsertEntry({
          source: 'smartbugs',
          sourceId: `sb-${contract.name}-${vuln.category}-${vuln.lines?.join('-') || 'unknown'}`,
          sourceUrl: contract.source,
          title: `${vuln.category.replace(/_/g, ' ')} in ${contract.name}`,
          description: `Vulnerability found in ${contract.name} at line(s) ${vuln.lines?.join(', ') || 'unknown'}. Category: ${vuln.category}. Pragma: ${contract.pragma}`,
          category: CATEGORY_MAP[vuln.category] || 'LOGIC_ERROR',
          severity: 'MEDIUM',
          tags: [vuln.category.replace(/_/g, ' '), 'academic', `solidity-${contract.pragma}`],
        });
      }
    }
    
    console.log(`   ✅ Processed SmartBugs entries`);
  } catch (error) {
    console.error('   ❌ Failed to sync SmartBugs:', error);
    stats.errors++;
  }
}

async function syncSWCRegistry() {
  console.log('\n📋 Syncing SWC Registry (37 vulnerability types)...\n');
  
  // SWC entries with detailed descriptions
  const swcEntries = [
    { id: 'SWC-100', title: 'Function Default Visibility', category: 'ACCESS_CONTROL', severity: 'MEDIUM',
      description: 'Functions that do not have a function visibility type specified are public by default. This can lead to a vulnerability if a developer forgot to set the visibility and a malicious user is able to make unauthorized or unintended state changes.' },
    { id: 'SWC-101', title: 'Integer Overflow and Underflow', category: 'ARITHMETIC', severity: 'HIGH',
      description: 'An overflow/underflow happens when an arithmetic operation reaches the maximum or minimum size of a type. For instance if a number is stored in the uint8 type, it means that the number is stored in a 8 bits unsigned number ranging from 0 to 2^8-1.' },
    { id: 'SWC-102', title: 'Outdated Compiler Version', category: 'LOGIC_ERROR', severity: 'INFO',
      description: 'Using an outdated compiler version can be problematic especially if there are publicly disclosed bugs and issues that affect the current compiler version.' },
    { id: 'SWC-103', title: 'Floating Pragma', category: 'LOGIC_ERROR', severity: 'LOW',
      description: 'Contracts should be deployed with the same compiler version and flags that they have been tested with thoroughly. Locking the pragma helps to ensure that contracts do not accidentally get deployed using, for example, an outdated compiler version.' },
    { id: 'SWC-104', title: 'Unchecked Call Return Value', category: 'EXTERNAL_INTERACTION', severity: 'MEDIUM',
      description: 'The return value of a message call is not checked. Execution will resume even if the called contract throws an exception. If the call fails accidentally or an attacker forces the call to fail, this may cause unexpected behaviour in the subsequent program logic.' },
    { id: 'SWC-105', title: 'Unprotected Ether Withdrawal', category: 'ACCESS_CONTROL', severity: 'CRITICAL',
      description: 'Due to missing or insufficient access controls, malicious parties can withdraw some or all Ether from the contract account.' },
    { id: 'SWC-106', title: 'Unprotected SELFDESTRUCT Instruction', category: 'ACCESS_CONTROL', severity: 'CRITICAL',
      description: 'Due to missing or insufficient access controls, malicious parties can self-destruct the contract.' },
    { id: 'SWC-107', title: 'Reentrancy', category: 'REENTRANCY', severity: 'HIGH',
      description: 'One of the major dangers of calling external contracts is that they can take over the control flow. In the reentrancy attack, a malicious contract calls back into the calling contract before the first invocation of the function is finished.' },
    { id: 'SWC-108', title: 'State Variable Default Visibility', category: 'ACCESS_CONTROL', severity: 'MEDIUM',
      description: 'Labeling the visibility explicitly makes it easier to catch incorrect assumptions about who can access the variable.' },
    { id: 'SWC-109', title: 'Uninitialized Storage Pointer', category: 'DATA_VALIDATION', severity: 'HIGH',
      description: 'Uninitialized local storage variables can point to unexpected storage locations in the contract, which can lead to intentional or unintentional vulnerabilities.' },
    { id: 'SWC-110', title: 'Assert Violation', category: 'LOGIC_ERROR', severity: 'MEDIUM',
      description: 'The Solidity assert() function is meant to assert invariants. Properly functioning code should never reach a failing assert statement.' },
    { id: 'SWC-111', title: 'Use of Deprecated Solidity Functions', category: 'LOGIC_ERROR', severity: 'LOW',
      description: 'Several functions and operators in Solidity are deprecated. Using them leads to reduced code quality. With new major versions of the Solidity compiler, deprecated functions and operators may result in side effects and compile errors.' },
    { id: 'SWC-112', title: 'Delegatecall to Untrusted Callee', category: 'ACCESS_CONTROL', severity: 'CRITICAL',
      description: 'There exists a special variant of a message call, named delegatecall which is identical to a message call apart from the fact that the code at the target address is executed in the context of the calling contract.' },
    { id: 'SWC-113', title: 'DoS with Failed Call', category: 'GAS_ISSUE', severity: 'MEDIUM',
      description: 'External calls can fail accidentally or deliberately, which can cause a DoS condition in the contract.' },
    { id: 'SWC-114', title: 'Transaction Order Dependence', category: 'ACCESS_CONTROL', severity: 'MEDIUM',
      description: 'The order of transactions is susceptible to manipulation. Miners can choose the order of transactions in a block, and priority is typically given to higher gas prices.' },
    { id: 'SWC-115', title: 'Authorization through tx.origin', category: 'ACCESS_CONTROL', severity: 'MEDIUM',
      description: 'tx.origin is a global variable in Solidity which returns the address of the account that sent the transaction. Using the variable for authorization could make a contract vulnerable if an authorized account calls a malicious contract.' },
    { id: 'SWC-116', title: 'Block values as a proxy for time', category: 'LOGIC_ERROR', severity: 'LOW',
      description: 'Contracts often need access to time values to perform certain types of functionality. Values such as block.timestamp and block.number can give you a sense of the current time or a time delta, but they can be manipulated by miners.' },
    { id: 'SWC-117', title: 'Signature Malleability', category: 'DATA_VALIDATION', severity: 'MEDIUM',
      description: 'The implementation of a cryptographic signature system in Ethereum contracts often assumes that the signature is unique, but signatures can be altered without the possession of the private key and still be valid.' },
    { id: 'SWC-118', title: 'Incorrect Constructor Name', category: 'ACCESS_CONTROL', severity: 'CRITICAL',
      description: 'Before Solidity version 0.4.22, the only way to define a constructor was to create a function with the same name as the contract. A function meant to be a constructor can be called by anyone if its name does not exactly match the contract name.' },
    { id: 'SWC-119', title: 'Shadowing State Variables', category: 'LOGIC_ERROR', severity: 'LOW',
      description: 'Solidity allows for ambiguous naming of state variables when inheritance is used. A derived contract can declare a state variable with the same name as a state variable in one of its base contracts.' },
    { id: 'SWC-120', title: 'Weak Sources of Randomness from Chain Attributes', category: 'LOGIC_ERROR', severity: 'HIGH',
      description: 'Ability to generate random numbers is very helpful in all kinds of applications. However, using chain attributes like block.timestamp, blockhash, or block.difficulty as a source of randomness is insecure.' },
    { id: 'SWC-121', title: 'Missing Protection against Signature Replay Attacks', category: 'DATA_VALIDATION', severity: 'HIGH',
      description: 'It is sometimes necessary to perform signature verification in smart contracts to achieve better usability or to save gas cost. A secure implementation needs to protect against Signature Replay Attacks.' },
    { id: 'SWC-122', title: 'Lack of Proper Signature Verification', category: 'DATA_VALIDATION', severity: 'HIGH',
      description: 'It is a common pattern for smart contract systems to allow users to sign messages off-chain instead of directly requesting users to do an on-chain transaction because of the flexibility and increased transferability that this provides.' },
    { id: 'SWC-123', title: 'Requirement Violation', category: 'LOGIC_ERROR', severity: 'MEDIUM',
      description: 'The Solidity require() construct is meant to validate external inputs of a function. In most cases, such external inputs are provided by callers, but they may also be returned by callees.' },
    { id: 'SWC-124', title: 'Write to Arbitrary Storage Location', category: 'ACCESS_CONTROL', severity: 'CRITICAL',
      description: 'A smart contract\'s data is persistently stored at some storage location on the EVM level. If an attacker can write to arbitrary storage locations of a contract, the authorization checks may easily be circumvented.' },
    { id: 'SWC-125', title: 'Incorrect Inheritance Order', category: 'LOGIC_ERROR', severity: 'MEDIUM',
      description: 'Solidity supports multiple inheritance, meaning that one contract can inherit several contracts. Multiple inheritance introduces ambiguity called Diamond Problem.' },
    { id: 'SWC-126', title: 'Insufficient Gas Griefing', category: 'GAS_ISSUE', severity: 'MEDIUM',
      description: 'Insufficient gas griefing attacks can be performed on contracts which accept data and use it in a sub-call on another contract. If the sub-call fails, either the whole transaction is reverted, or execution is continued.' },
    { id: 'SWC-127', title: 'Arbitrary Jump with Function Type Variable', category: 'ACCESS_CONTROL', severity: 'HIGH',
      description: 'Solidity supports function types. That is, a variable of function type can be assigned with a reference to a function with a matching signature. An attacker may be able to make a contract jump to any code address.' },
    { id: 'SWC-128', title: 'DoS With Block Gas Limit', category: 'GAS_ISSUE', severity: 'MEDIUM',
      description: 'When smart contracts are deployed or functions inside them are called, the execution of these actions always requires a certain amount of gas. If the gas requirement exceeds the block gas limit, the transaction fails.' },
    { id: 'SWC-129', title: 'Typographical Error', category: 'LOGIC_ERROR', severity: 'LOW',
      description: 'A typographical error can occur for example when the intent of a defined operation is to sum a number to a variable (+=) but it has accidentally been defined in a way that subtracts the value (-=).' },
    { id: 'SWC-130', title: 'Right-To-Left-Override control character (U+202E)', category: 'LOGIC_ERROR', severity: 'LOW',
      description: 'Malicious actors can use the Right-To-Left-Override unicode character to force RTL text rendering and confuse users as to the real intent of a contract.' },
    { id: 'SWC-131', title: 'Presence of unused variables', category: 'GAS_ISSUE', severity: 'INFO',
      description: 'Unused variables are allowed in Solidity and they do not pose a direct security issue. It is best practice though to avoid them as they can decrease readability and increase maintenance cost.' },
    { id: 'SWC-132', title: 'Unexpected Ether balance', category: 'LOGIC_ERROR', severity: 'MEDIUM',
      description: 'Contracts can behave erroneously when they strictly assume a specific Ether balance. It is always possible to forcibly send ether to a contract via selfdestruct or mining coinbase.' },
    { id: 'SWC-133', title: 'Hash Collisions With Multiple Variable Length Arguments', category: 'DATA_VALIDATION', severity: 'MEDIUM',
      description: 'Using abi.encodePacked() with multiple variable length arguments can, in certain situations, lead to a hash collision.' },
    { id: 'SWC-134', title: 'Message call with hardcoded gas amount', category: 'EXTERNAL_INTERACTION', severity: 'LOW',
      description: 'The transfer() and send() functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers.' },
    { id: 'SWC-135', title: 'Code With No Effects', category: 'LOGIC_ERROR', severity: 'INFO',
      description: 'In Solidity, code can be written that does not produce the intended effects. In the example below, the condition check will always evaluate to true because a = 1 assigns the value.' },
    { id: 'SWC-136', title: 'Unencrypted Private Data On-Chain', category: 'DATA_VALIDATION', severity: 'HIGH',
      description: 'It is a common misconception that private type variables cannot be read. Even if your contract is not published, attackers can look at contract transactions to determine values stored in the state of the contract.' },
  ];
  
  try {
    for (const swc of swcEntries) {
      await upsertEntry({
        source: 'swc-registry',
        sourceId: swc.id,
        sourceUrl: `https://swcregistry.io/docs/${swc.id}`,
        title: `${swc.id}: ${swc.title}`,
        description: swc.description,
        category: swc.category as any,
        severity: swc.severity as any,
        tags: [swc.id.toLowerCase(), swc.title.toLowerCase().replace(/\s+/g, '-'), 'standard'],
      });
    }
    
    console.log(`   ✅ Processed ${swcEntries.length} SWC entries`);
  } catch (error) {
    console.error('   ❌ Failed to sync SWC Registry:', error);
    stats.errors++;
  }
}

async function syncCommonPatterns() {
  console.log('\n🎯 Adding common vulnerability patterns...\n');
  
  const patterns = [
    // Reentrancy patterns
    { title: 'Classic Reentrancy via External Call', category: 'REENTRANCY', severity: 'CRITICAL',
      description: 'External call to untrusted contract before state update allows attacker to re-enter and drain funds.',
      remediation: 'Use checks-effects-interactions pattern. Update state before external calls. Use ReentrancyGuard.' },
    { title: 'Cross-Function Reentrancy', category: 'REENTRANCY', severity: 'HIGH',
      description: 'Attacker exploits shared state between functions during reentrancy callback.',
      remediation: 'Apply reentrancy guard to all functions sharing state.' },
    { title: 'Read-Only Reentrancy', category: 'REENTRANCY', severity: 'HIGH',
      description: 'View functions return stale values during callback, causing incorrect calculations.',
      remediation: 'Be aware of state changes during external calls. Consider reentrancy locks for view functions that depend on mutable state.' },
    { title: 'Cross-Contract Reentrancy', category: 'REENTRANCY', severity: 'HIGH',
      description: 'Attacker exploits callbacks between multiple contracts in the protocol.',
      remediation: 'Apply protocol-wide reentrancy protection.' },
    
    // Oracle patterns
    { title: 'Spot Price Manipulation via Flash Loan', category: 'ORACLE_MANIPULATION', severity: 'CRITICAL',
      description: 'Protocol uses DEX spot price which can be manipulated within a single transaction using flash loans.',
      remediation: 'Use TWAP oracles, Chainlink price feeds, or time-weighted calculations.' },
    { title: 'Stale Oracle Price', category: 'ORACLE_MANIPULATION', severity: 'HIGH',
      description: 'Oracle price staleness not checked, allowing use of outdated prices.',
      remediation: 'Check oracle timestamp and heartbeat. Implement staleness threshold.' },
    { title: 'Oracle Price Deviation', category: 'ORACLE_MANIPULATION', severity: 'MEDIUM',
      description: 'No check for extreme price deviations that could indicate oracle manipulation.',
      remediation: 'Implement circuit breakers for abnormal price movements.' },
    
    // Access control patterns
    { title: 'Missing Access Control', category: 'ACCESS_CONTROL', severity: 'CRITICAL',
      description: 'Critical function lacks access modifier allowing unauthorized execution.',
      remediation: 'Add onlyOwner, onlyAdmin, or role-based access control.' },
    { title: 'Centralization Risk', category: 'ACCESS_CONTROL', severity: 'MEDIUM',
      description: 'Single admin key controls critical protocol functions without timelock.',
      remediation: 'Implement multisig, timelock, and decentralized governance.' },
    { title: 'Front-Running Vulnerability', category: 'ACCESS_CONTROL', severity: 'MEDIUM',
      description: 'Transaction can be front-run by MEV bots observing mempool.',
      remediation: 'Use commit-reveal schemes, private mempools, or slippage protection.' },
    
    // Token handling patterns
    { title: 'Fee-On-Transfer Token Not Supported', category: 'TOKEN_HANDLING', severity: 'MEDIUM',
      description: 'Protocol assumes received amount equals transferred amount, breaks with fee tokens.',
      remediation: 'Check actual balance received vs amount transferred.' },
    { title: 'Rebasing Token Issues', category: 'TOKEN_HANDLING', severity: 'MEDIUM',
      description: 'Protocol caches token balances without accounting for rebasing.',
      remediation: 'Use shares instead of amounts for rebasing tokens.' },
    { title: 'ERC777 Callback Exploitation', category: 'TOKEN_HANDLING', severity: 'HIGH',
      description: 'ERC777 hooks enable reentrancy attacks on token transfers.',
      remediation: 'Use reentrancy guards on all token transfer functions.' },
    
    // Arithmetic patterns
    { title: 'Division Before Multiplication', category: 'ARITHMETIC', severity: 'MEDIUM',
      description: 'Precision loss due to integer division before multiplication.',
      remediation: 'Always multiply before dividing. Use higher precision intermediates.' },
    { title: 'Unsafe Downcast', category: 'ARITHMETIC', severity: 'HIGH',
      description: 'Casting larger integer to smaller type without bounds checking.',
      remediation: 'Use SafeCast library or explicit bounds checks.' },
    { title: 'Rounding Error Exploitation', category: 'ARITHMETIC', severity: 'MEDIUM',
      description: 'Attacker exploits rounding direction to extract value.',
      remediation: 'Round in favor of the protocol. Use consistent rounding direction.' },
    
    // Gas/DoS patterns
    { title: 'Unbounded Loop DoS', category: 'GAS_ISSUE', severity: 'MEDIUM',
      description: 'Loop iterates over unbounded array causing out-of-gas failures.',
      remediation: 'Implement pagination or limit array sizes.' },
    { title: 'Block Gas Limit DoS', category: 'GAS_ISSUE', severity: 'MEDIUM',
      description: 'Operation requires more gas than block limit allows.',
      remediation: 'Break operation into smaller chunks. Allow partial processing.' },
    
    // Logic error patterns
    { title: 'Incorrect State Transition', category: 'LOGIC_ERROR', severity: 'HIGH',
      description: 'State machine allows invalid transitions or skipping required steps.',
      remediation: 'Implement proper state machine with explicit transition rules.' },
    { title: 'Off-By-One Error', category: 'LOGIC_ERROR', severity: 'MEDIUM',
      description: 'Loop or array bounds off by one causing under/over-processing.',
      remediation: 'Review all loop bounds and array indexing carefully.' },
    { title: 'Uninitialized Variable', category: 'LOGIC_ERROR', severity: 'HIGH',
      description: 'Critical variable used before initialization, defaulting to zero or unexpected value.',
      remediation: 'Initialize all variables explicitly. Add initialization checks.' },
  ];
  
  try {
    for (const pattern of patterns) {
      await upsertEntry({
        source: 'patterns',
        sourceId: `pattern-${pattern.title.toLowerCase().replace(/\s+/g, '-')}`,
        title: pattern.title,
        description: `${pattern.description}\n\nRemediation: ${pattern.remediation}`,
        category: pattern.category as any,
        severity: pattern.severity as any,
        tags: [pattern.category.toLowerCase().replace(/_/g, '-'), 'pattern', 'common'],
      });
    }
    
    console.log(`   ✅ Added ${patterns.length} common patterns`);
  } catch (error) {
    console.error('   ❌ Failed to add patterns:', error);
    stats.errors++;
  }
}

// Helper functions
async function upsertEntry(entry: {
  source: string;
  sourceId: string;
  sourceUrl?: string;
  title: string;
  description: string;
  category?: string;
  severity?: string;
  tags?: string[];
  publishedAt?: Date;
}) {
  stats.total++;
  
  try {
    const existing = await db.knowledgeBaseEntry.findFirst({
      where: { source: entry.source, sourceId: entry.sourceId },
    });
    
    if (existing) {
      await db.knowledgeBaseEntry.update({
        where: { id: existing.id },
        data: {
          title: entry.title,
          description: entry.description,
          category: entry.category as any,
          severity: entry.severity as any,
          tags: entry.tags || [],
          sourceUrl: entry.sourceUrl,
          publishedAt: entry.publishedAt,
        },
      });
      stats.updated++;
    } else {
      await db.knowledgeBaseEntry.create({
        data: {
          source: entry.source,
          sourceId: entry.sourceId,
          sourceUrl: entry.sourceUrl,
          title: entry.title,
          description: entry.description,
          category: entry.category as any,
          severity: entry.severity as any,
          tags: entry.tags || [],
          publishedAt: entry.publishedAt,
        },
      });
      stats.added++;
    }
  } catch (error) {
    stats.errors++;
  }
}

function inferCategory(text: string): string {
  const lower = text.toLowerCase();
  for (const [key, value] of Object.entries(CATEGORY_MAP)) {
    if (lower.includes(key)) return value;
  }
  return 'LOGIC_ERROR';
}

function inferSeverity(text: string): string {
  const lower = text.toLowerCase();
  if (lower.includes('critical') || lower.includes('drain') || lower.includes('steal')) return 'CRITICAL';
  if (lower.includes('high') || lower.includes('manipulation') || lower.includes('reentrancy')) return 'HIGH';
  if (lower.includes('medium') || lower.includes('incorrect')) return 'MEDIUM';
  return 'HIGH'; // Default to HIGH for real exploits
}

function parseDate(dateStr: string): Date | undefined {
  if (!dateStr || dateStr.length !== 8) return undefined;
  const year = parseInt(dateStr.slice(0, 4));
  const month = parseInt(dateStr.slice(4, 6)) - 1;
  const day = parseInt(dateStr.slice(6, 8));
  return new Date(year, month, day);
}

// Main
async function main() {
  console.log('═'.repeat(60));
  console.log('🚀 Full Knowledge Base Sync');
  console.log('═'.repeat(60));
  
  await syncSWCRegistry();
  await syncSmartBugs();
  await syncDeFiHackLabs();
  await syncCommonPatterns();
  
  console.log('\n' + '═'.repeat(60));
  console.log('📊 Final Summary');
  console.log('═'.repeat(60));
  console.log(`Total processed: ${stats.total}`);
  console.log(`  ✅ Added: ${stats.added}`);
  console.log(`  🔄 Updated: ${stats.updated}`);
  console.log(`  ❌ Errors: ${stats.errors}`);
  console.log('═'.repeat(60));
  
  // Get final count
  const count = await db.knowledgeBaseEntry.count();
  console.log(`\n📚 Total entries in knowledge base: ${count}`);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
