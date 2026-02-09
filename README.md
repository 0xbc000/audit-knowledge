# Audit Knowledge Base 🔍

A curated collection of smart contract vulnerability patterns, audit checklists, and automated detection tools — built from analyzing real audit contests and security incidents.

## Structure

```
├── data/
│   ├── patterns/              # Attack pattern documentation
│   │   ├── cross-contract-attack-patterns.md
│   │   ├── dex-business-logic-patterns.md
│   │   ├── economic-attack-vectors.md
│   │   ├── lending-protocol-patterns.md
│   │   ├── privilege-escalation-patterns.md
│   │   └── yield-tokenization-patterns.md
│   └── vulnerabilities/       # Categorized vulnerability knowledge
│       ├── checklists/        # Audit checklists by protocol type
│       │   ├── callback-integration-checklist.md
│       │   ├── dex-audit-checklist.md
│       │   ├── general-audit-checklist.md
│       │   ├── l2-emerging-checklist.md
│       │   ├── lending-audit-checklist.md
│       │   └── yield-audit-checklist.md
│       ├── cross-protocol/    # Cross-protocol & oracle risks
│       ├── economic/          # MEV, liquidation, state transitions
│       └── protocol-specific/ # Per-protocol vulnerability patterns
│           ├── dex-amm.md
│           ├── lending.md
│           ├── staking-lsd.md
│           ├── l2-specific.md
│           ├── emerging-protocols.md
│           ├── cryptographic-primitives.md
│           └── ...
├── tools/
│   ├── slither-detectors/     # Custom Slither detectors
│   │   ├── mev_risks.py
│   │   ├── l2_specific.py
│   │   ├── emerging_protocols.py
│   │   ├── cryptographic_primitives.py
│   │   ├── fcfs_tiering.py
│   │   └── admin_security.py
│   └── foundry-templates/     # Reusable invariant test templates
│       ├── DeFiInvariantBase.sol
│       ├── LendingInvariantTest.t.sol
│       ├── VaultInvariantTest.t.sol
│       ├── AdminSecurityInvariantTest.t.sol
│       ├── CryptographicInvariantTest.t.sol
│       └── FCFSTieringInvariantTest.t.sol
├── benchmarks/                # Real audit contest analyses
└── src/                       # Auditor engine (TypeScript)
```

## Coverage

### Vulnerability Patterns
- **DeFi Protocols**: DEX/AMM, Lending, Staking/LSD, Yield Tokenization
- **Economic Attacks**: MEV (sandwich, JIT liquidity), Flash loan vectors, Liquidation cascades
- **Cross-Protocol**: Oracle manipulation, External integration risks
- **L2 Specific**: Sequencer downtime, L1↔L2 message delay, Gas calculation differences
- **Emerging**: Restaking (EigenLayer), Intent-based protocols, Points/Airdrop systems
- **Cryptographic**: ECDSA edge cases, Merkle tree vulnerabilities, Hash collision risks

### Audit Checklists
Protocol-specific checklists for systematic auditing — each covers common pitfalls, invariants to check, and known attack vectors.

### Automated Tools
- **Slither Detectors**: Custom detectors for MEV risks, L2 issues, emerging protocol patterns
- **Foundry Templates**: Reusable invariant test templates for DeFi protocols (lending, vaults, admin security)

## Usage

### Slither Detectors
```bash
slither . --detect mev-risks,l2-specific --additional-detectors tools/slither-detectors/
```

### Foundry Invariant Tests
```bash
# Import the base contract and extend for your protocol
import {DeFiInvariantBase} from "tools/foundry-templates/DeFiInvariantBase.sol";
```

## Key Insight

> Effective AI-assisted auditing isn't about having AI read all the code at once. It's about:
> 1. **Human builds context** — protocol design, invariants, trust assumptions
> 2. **AI deep-dives specific areas** — targeted analysis with proper context
> 3. **Iterative questioning** — follow-up on suspicious patterns
> 4. **One function at a time** — focused, thorough analysis

## License

MIT
