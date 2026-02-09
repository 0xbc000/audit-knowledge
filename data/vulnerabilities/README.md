# Vulnerability Knowledge Base

This directory contains categorized vulnerability patterns extracted from real audit contests and security research.

## Structure

```
vulnerabilities/
├── protocol-specific/              # Protocol-type specific vulnerabilities
│   ├── dex-amm.md                 # DEX/AMM vulnerabilities
│   ├── lending.md                 # Lending protocol vulnerabilities
│   ├── staking-lsd.md             # Staking and LSD vulnerabilities
│   ├── callback-security.md       # ERC721/1155 callback exploitation
│   ├── uniswap-v3-integration.md  # Uniswap V3 TWAP/tick math
│   ├── eip-compliance.md          # ERC-4626, ERC-20 compliance issues
│   ├── l2-specific.md             # L2/Rollup vulnerabilities ⭐ NEW 2026-02-05
│   ├── emerging-protocols.md      # Restaking/Intent/Points ⭐ NEW 2026-02-05
│   ├── yield-tokenization.md      # Yield/PT/YT vulnerabilities
│   ├── perpetuals.md              # Perpetual/derivatives vulnerabilities
│   ├── bridges.md                 # Cross-chain bridge vulnerabilities
│   └── governance.md              # Governance/DAO vulnerabilities
│
├── cross-protocol/                 # Cross-protocol interaction risks
│   ├── oracle-manipulation.md     # Oracle and price feed attacks
│   ├── external-integration.md    # External protocol dependency risks
│   └── composability-risks.md     # DeFi composability attack vectors
│
├── economic/                       # Economic attack vectors
│   ├── liquidation-risks.md       # Liquidation gaming and risks
│   ├── state-transition-risks.md  # Protocol state change vulnerabilities
│   ├── mev-patterns.md            # MEV attack patterns (~20KB)
│   └── flash-loan-vectors.md      # Flash loan attack patterns
│
└── checklists/                     # Audit checklists by protocol type
    ├── general-audit-checklist.md
    ├── dex-audit-checklist.md
    ├── lending-audit-checklist.md
    ├── yield-audit-checklist.md
    ├── callback-integration-checklist.md
    └── l2-emerging-checklist.md   # ⭐ NEW - L2 & emerging protocol audit
```

## New Files (2026-02-04)

### Based on Revert Lend Benchmark False Negatives:

1. **callback-security.md** (~9.5 KB)
   - ERC721/1155 callback DoS patterns
   - Liquidation callback blocking
   - Reentrancy via safeTransferFrom
   - Gas griefing via callbacks

2. **uniswap-v3-integration.md** (~12.3 KB)
   - TWAP tick rounding errors (H-05 fix)
   - Tick spacing violations
   - Price calculation precision
   - Position valuation errors
   - Observation cardinality checks

3. **eip-compliance.md** (~10.8 KB)
   - ERC-4626 vault compliance
   - ERC-20 edge cases (fee-on-transfer, rebasing)
   - ERC-721/1155 compliance
   - ERC-2612 permit issues

4. **state-transition-risks.md** (~13.1 KB)
   - Feature disable with active positions
   - Config removal without cleanup
   - Asymmetric add/remove operations
   - Parameter changes without state update

5. **callback-integration-checklist.md** (~6.3 KB)
   - Systematic callback security review
   - External integration validation
   - Oracle integration checks
   - State transition safety

**Total new content: ~52 KB**

### New Files (2026-02-05 02:00 AM)

6. **mev-patterns.md** (~20 KB)
   - Sandwich attack patterns & defenses
   - JIT (Just-In-Time) liquidity attacks
   - Oracle manipulation via MEV
   - Liquidation MEV (front-running, block stuffing)
   - Protocol-level MEV defenses (commit-reveal, batch auctions, Dutch auctions)
   - Real-world case studies (Mango Markets, Euler Finance)
   - Comprehensive audit checklist for MEV vulnerabilities

### New Files (2026-02-05 04:00 AM) - L2 & Emerging Protocols

7. **l2-specific.md** (~19 KB)
   - Sequencer downtime and censorship attacks
   - L1→L2 message delay exploitation
   - Retryable ticket manipulation (Arbitrum)
   - L2 gas calculation vulnerabilities (L1 data fees)
   - Address aliasing issues
   - L2-specific precompile risks (ArbSys, zkSync system contracts)
   - Cross-L2 bridge vulnerabilities
   - State finality and reorg risks
   - Complete L2 audit checklist

8. **emerging-protocols.md** (~25 KB)
   - **Restaking (EigenLayer, Symbiotic)**
     - Slashing cascade vulnerabilities
     - Operator collusion attacks
     - Withdrawal timing attacks
     - Delegation race conditions
     - AVS registration manipulation
   - **Intent-Based Protocols (CoW, UniswapX)**
     - Intent manipulation attacks
     - Solver collusion and MEV extraction
     - Intent replay attacks
     - Partial fill exploitation
     - Cross-intent MEV
   - **Points/Airdrop Systems**
     - Sybil farming attacks
     - Flash loan points manipulation
     - Referral system exploitation
     - Airdrop claim vulnerabilities
     - Merkle proof attacks
     - Points-to-token conversion gaming

9. **l2-emerging-checklist.md** (~10 KB)
   - Part A: L2 Specific Checklist (sequencer, messaging, gas, features, bridges, finality)
   - Part B: Restaking Protocol Checklist (slashing, operators, delegation, AVS, withdrawals)
   - Part C: Intent-Based Protocol Checklist (specification, replay, solvers, fills, settlement)
   - Part D: Points/Airdrop System Checklist (sybil, accumulation, referrals, claims, conversion)
   - Quick reference for critical vulnerabilities by protocol type

**Total L2/Emerging content: ~54 KB**
**Grand total knowledge base: ~206 KB** (19 files)

## Usage

When auditing a specific protocol type:
1. Load the relevant protocol-specific vulnerability file
2. Cross-reference with cross-protocol risks
3. Use the appropriate checklist during manual review

### For Lending Protocols (Uniswap V3 LP collateral):
```
- protocol-specific/lending.md
- protocol-specific/callback-security.md     ⭐ NEW
- protocol-specific/uniswap-v3-integration.md ⭐ NEW
- economic/liquidation-risks.md
- economic/state-transition-risks.md         ⭐ NEW
- checklists/lending-audit-checklist.md
- checklists/callback-integration-checklist.md ⭐ NEW
```

### For DEX/AMM Protocols:
```
- protocol-specific/dex-amm.md
- protocol-specific/uniswap-v3-integration.md ⭐ NEW
- cross-protocol/oracle-manipulation.md
- checklists/dex-audit-checklist.md
```

## Sources

Patterns are extracted from:
- Code4rena contest findings (Revert Lend, Salty.IO, etc.)
- Sherlock audit reports (AAVE v3.3, Napier Finance, etc.)
- Immunefi bug bounties
- Academic security research
- Real-world exploits (Rekt News, DeFiHackLabs)

## Last Updated
2026-02-05 04:00 AM (Asia/Taipei)
