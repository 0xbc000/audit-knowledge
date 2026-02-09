# L2 & Emerging Protocols Audit Checklist

Comprehensive checklist for auditing Layer 2 deployments and emerging protocol types (Restaking, Intent-based, Points/Airdrops).

---

## Part A: Layer 2 Specific Checklist

### A1. Sequencer Risk Assessment

| Check | Status | Notes |
|-------|--------|-------|
| **Downtime Protection** | | |
| Uses Chainlink Sequencer Uptime Feed? | ☐ | Required for Arbitrum/Optimism |
| Grace period after sequencer resumes? | ☐ | Recommended: 1-3 hours |
| Time-sensitive operations protected? | ☐ | Liquidations, auctions, deadlines |
| L1 escape hatch available for withdrawals? | ☐ | Users can bypass sequencer |
| **Censorship Resistance** | | |
| Commit-reveal for sensitive operations? | ☐ | Prevents sequencer censorship |
| Force-inclusion mechanism documented? | ☐ | Users know how to use L1 fallback |
| No reliance on sequential L2 txs for critical paths? | ☐ | Single tx should be atomic |

### A2. Cross-Chain Messaging

| Check | Status | Notes |
|-------|--------|-------|
| **L1 → L2 Messages** | | |
| Message delays accounted for in price feeds? | ☐ | Minimum 10-15 min staleness assumed |
| L1 timestamp passed and validated? | ☐ | Don't trust L2 block.timestamp for L1 data |
| Retryable ticket handling (Arbitrum)? | ☐ | Tickets can be redeemed later |
| Message expiration enforced? | ☐ | Old messages should be rejected |
| **L2 → L1 Messages** | | |
| Withdrawal finalization properly validated? | ☐ | 7-day challenge for optimistic rollups |
| Double-processing prevented? | ☐ | Message hash marked as used |
| Rate limiting on withdrawals? | ☐ | Prevent bridge drainage attacks |
| **General** | | |
| Message replay attacks prevented? | ☐ | Unique identifiers/nonces |
| Cross-chain admin functions protected? | ☐ | Verify source chain/contract |

### A3. Gas and Execution

| Check | Status | Notes |
|-------|--------|-------|
| **L2 Gas Costs** | | |
| L1 data fees accounted for? | ☐ | Arbitrum: ArbGasInfo, OP: GasPriceOracle |
| Variable L1 gas handled gracefully? | ☐ | Don't hardcode L1 gas costs |
| Batch operations respect L2 gas limits? | ☐ | Limits differ from mainnet |
| **Execution Differences** | | |
| Block number interpretation correct? | ☐ | L2 blocks != L1 blocks |
| Block timestamp differences handled? | ☐ | L2 timestamps more granular |
| Precompile availability verified? | ☐ | Not all precompiles available on all L2s |

### A4. L2-Specific Features

| Check | Status | Notes |
|-------|--------|-------|
| **Address Aliasing** | | |
| Cross-chain calls handle aliasing? | ☐ | L1 address + offset on L2 |
| AddressAliasHelper used correctly? | ☐ | Arbitrum/Optimism specific |
| **Deployment** | | |
| CREATE2 addresses calculated correctly? | ☐ | zkSync uses different formula |
| Contract verification on L2 explorer? | ☐ | Block explorers differ |
| **ZK-Specific (if applicable)** | | |
| zkSync system contracts understood? | ☐ | ContractDeployer, Bootloader |
| Prover delays accounted for? | ☐ | ZK proof generation time |

### A5. Bridge Integration

| Check | Status | Notes |
|-------|--------|-------|
| Only trusted bridges whitelisted? | ☐ | Canonical bridge preferred |
| Bridge message proofs validated? | ☐ | Don't trust caller claims |
| Token representation consistent? | ☐ | Same token = different addresses |
| Bridge failure modes handled? | ☐ | What if bridge is paused? |

### A6. Finality Considerations

| Check | Status | Notes |
|-------|--------|-------|
| Soft vs hard finality distinguished? | ☐ | Don't act on unfinalized state |
| Cross-chain arbitrage reorg-safe? | ☐ | L2 can reorg before L1 finalization |
| Critical operations wait for finality? | ☐ | Configurable delay recommended |

### A7. Admin and Upgrade Security (L2-Specific)

| Check | Status | Notes |
|-------|--------|-------|
| **Key Management** | | |
| Admin keys stored in hardware wallet? | ☐ | Single point of failure mitigation |
| Multi-sig required for admin operations? | ☐ | 2-of-3 minimum |
| Different admin keys per protocol? | ☐ | Shared deployer = shared risk |
| **Upgrade Protection** | | |
| Proxy upgrade requires timelock? | ☐ | Minimum 48h recommended |
| Timelock > L2→L1 bridge delay? | ☐ | Give time for L1 monitoring response |
| L1 notified on upgrade proposal? | ☐ | Cross-chain monitoring |
| **Bridge Exit Monitoring** | | |
| Large withdrawal alerts configured? | ☐ | Detect drain attempts |
| Admin operations logged cross-chain? | ☐ | L1 visibility into L2 ops |
| Emergency pause available? | ☐ | Can freeze before bridge exit |

---

## Part B: Restaking Protocol Checklist

### B1. Slashing Mechanism

| Check | Status | Notes |
|-------|--------|-------|
| **Isolation** | | |
| Slashing capped per AVS? | ☐ | Prevent cascade |
| Max slashing percentage defined? | ☐ | e.g., 50% per offense |
| Slashing isolated to allocated stake? | ☐ | Other AVSs unaffected |
| **Process** | | |
| Slashing evidence required? | ☐ | On-chain verifiable proof |
| Challenge period for disputed slashing? | ☐ | Operators can dispute |
| Slashing window vs withdrawal delay? | ☐ | Can't escape by withdrawing |

### B2. Operator Management

| Check | Status | Notes |
|-------|--------|-------|
| **Registration** | | |
| Operator minimum bond required? | ☐ | Skin in the game |
| Operator concentration limited? | ☐ | e.g., max 33% of total stake |
| **Deregistration** | | |
| Deregistration delay enforced? | ☐ | Can't rage-quit before slashing |
| Pending slashings prevent deregistration? | ☐ | Freeze mechanism |

### B3. Delegation

| Check | Status | Notes |
|-------|--------|-------|
| Delegation changes queued? | ☐ | No immediate effect |
| Undelegation delay sufficient? | ☐ | Minimum 7 days typical |
| Circular delegation prevented? | ☐ | Operator → Operator loops |
| Delegation limits per operator? | ☐ | Concentration risk |

### B4. AVS Integration

| Check | Status | Notes |
|-------|--------|-------|
| AVS registration gated? | ☐ | Governance/timelock required |
| AVS code hash verified? | ☐ | Detect upgrades/changes |
| Economic security calculation? | ☐ | Collateral > value at risk |
| Slashing conditions clearly defined? | ☐ | Unambiguous offense criteria |

### B5. Withdrawals

| Check | Status | Notes |
|-------|--------|-------|
| Withdrawal queue implemented? | ☐ | No instant withdrawals |
| Delay exceeds slashing detection window? | ☐ | 7+ days typical |
| Frozen accounts can't complete withdrawal? | ☐ | Pending investigation blocks |
| Partial withdrawal supported safely? | ☐ | Maintain minimum stake |

---

## Part C: Intent-Based Protocol Checklist

### C1. Intent Specification

| Check | Status | Notes |
|-------|--------|-------|
| **Completeness** | | |
| Minimum output amount required? | ☐ | User protection floor |
| Price oracle reference optional? | ☐ | Better than min alone |
| Slippage tolerance specified? | ☐ | Basis points from oracle |
| Deadline/expiration included? | ☐ | Prevent stale execution |
| **Validation** | | |
| Intent signature verified? | ☐ | EIP-712 recommended |
| Signer matches beneficiary or delegate? | ☐ | Authorization check |

### C2. Replay Protection

| Check | Status | Notes |
|-------|--------|-------|
| Nonce implemented? | ☐ | Per-user sequential |
| Intent hash marked as used? | ☐ | Prevent double-fill |
| Cross-chain replay prevented? | ☐ | Chain ID in signature |
| Cancellation mechanism exists? | ☐ | User can invalidate intent |

### C3. Solver Management

| Check | Status | Notes |
|-------|--------|-------|
| **Registration** | | |
| Solver bond required? | ☐ | Minimum stake |
| Solver reputation tracked? | ☐ | Fill quality metrics |
| **Enforcement** | | |
| Slashing for provably bad fills? | ☐ | Below oracle threshold |
| Solver competition ensured? | ☐ | No single solver monopoly |

### C4. Fill Mechanics

| Check | Status | Notes |
|-------|--------|-------|
| Partial fills handled fairly? | ☐ | No cherry-picking |
| Minimum fill percentage if partial? | ☐ | e.g., 80% minimum |
| All-or-nothing option available? | ☐ | User choice |
| Fill ordering MEV-resistant? | ☐ | Batch auctions preferred |

### C5. Settlement

| Check | Status | Notes |
|-------|--------|-------|
| Atomic settlement? | ☐ | All-or-nothing execution |
| User receives tokens directly? | ☐ | Not intermediate custody |
| Settlement verification on-chain? | ☐ | Provable execution |
| Gas costs fair? | ☐ | Solver doesn't overcharge |

---

## Part D: Points/Airdrop System Checklist

### D1. Sybil Resistance

| Check | Status | Notes |
|-------|--------|-------|
| Human verification integrated? | ☐ | Worldcoin, Gitcoin Passport |
| Wallet age/history considered? | ☐ | New wallets penalized |
| Minimum transaction count? | ☐ | Activity threshold |
| Gas cost makes farming unprofitable? | ☐ | Economic Sybil resistance |

### D2. Points Accumulation

| Check | Status | Notes |
|-------|--------|-------|
| **Flash Loan Resistance** | | |
| Time-weighted average balance? | ☐ | Not snapshot-based |
| Observation frequency sufficient? | ☐ | At least daily |
| Lock period for bonus points? | ☐ | Can't deposit-and-exit |
| **Farming Resistance** | | |
| Wash trading detection? | ☐ | Same-wallet loops flagged |
| Maximum points per action? | ☐ | Diminishing returns |
| Cooldown between earning actions? | ☐ | Rate limiting |

### D3. Referral System

| Check | Status | Notes |
|-------|--------|-------|
| Self-referral prevented? | ☐ | Direct check |
| Circular referral prevented? | ☐ | Chain traversal check |
| Referral depth limited? | ☐ | e.g., max 3 levels |
| Referrer activity required? | ☐ | Dead referrers don't earn |

### D4. Airdrop Claims

| Check | Status | Notes |
|-------|--------|-------|
| **Merkle Proof** | | |
| Double-hashing for leaves? | ☐ | Prevent second preimage |
| Proof verification gas-efficient? | ☐ | OpenZeppelin library |
| Root immutable after snapshot? | ☐ | No post-hoc changes |
| **Claims** | | |
| Claim deadline enforced? | ☐ | 90 days typical |
| Unclaimed token recovery? | ☐ | Treasury can reclaim |
| Double-claim prevented? | ☐ | claimed[address] = true |
| Delegate claiming supported? | ☐ | For multisigs/contracts |

### D5. Points-to-Token Conversion

| Check | Status | Notes |
|-------|--------|-------|
| Conversion rate fair? | ☐ | Pro-rata preferred |
| Total points snapshot immutable? | ☐ | No manipulation after lock |
| Conversion window bounded? | ☐ | Start and end dates |
| Market manipulation resistant? | ☐ | Conversion independent of price |

---

## Quick Reference: Critical Vulnerabilities by Protocol Type

### L2 Critical Issues
1. ❌ No sequencer uptime check
2. ❌ Cross-chain message replay possible
3. ❌ Ignoring L1 data fees
4. ❌ Instant finality assumptions

### Restaking Critical Issues
1. ❌ Unbounded slashing cascade
2. ❌ Instant withdrawal allowing slashing escape
3. ❌ No operator concentration limits
4. ❌ AVS registration without governance

### Intent Critical Issues
1. ❌ No replay protection (missing nonce)
2. ❌ Underspecified intents (no oracle reference)
3. ❌ No solver accountability (no bond/slashing)
4. ❌ Partial fill cherry-picking

### Points/Airdrop Critical Issues
1. ❌ Snapshot-based (flash loan vulnerable)
2. ❌ No Sybil resistance
3. ❌ Circular referrals possible
4. ❌ Single-hash merkle leaves

---

*Checklist created: 2026-02-05 04:00 AM*
*Version: 1.0*
