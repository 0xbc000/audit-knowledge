# General Smart Contract Audit Checklist

A comprehensive checklist for auditing any DeFi protocol.

---

## 1. Access Control

### Administrative Functions
- [ ] All admin functions have proper access control
- [ ] Multi-sig required for critical operations
- [ ] Timelock on sensitive parameter changes
- [ ] Renounce/transfer ownership properly implemented
- [ ] No hidden admin backdoors

### Role Management
- [ ] Role hierarchy clearly defined
- [ ] Role assignment properly gated
- [ ] Role revocation possible
- [ ] No role confusion between contracts

### Pause Functionality
- [ ] Pause mechanism exists for emergencies
- [ ] Pause can't be abused by admin
- [ ] Critical withdrawals still possible when paused
- [ ] Pause state properly checked everywhere

---

## 2. Input Validation

### Parameter Bounds
- [ ] Array lengths bounded (no unbounded loops)
- [ ] Numeric parameters have min/max checks
- [ ] Addresses checked for zero address
- [ ] Amounts checked for zero (where relevant)

### External Input
- [ ] User-provided addresses validated
- [ ] Callback data validated
- [ ] Signatures properly verified
- [ ] Deadline parameters checked

### State Requirements
- [ ] Preconditions checked before state changes
- [ ] Contract not called in unexpected states
- [ ] Initialization can only happen once

---

## 3. Arithmetic & Precision

### Overflow/Underflow
- [ ] Using Solidity 0.8+ or SafeMath
- [ ] Explicit unchecked blocks reviewed carefully
- [ ] Type casting checked for truncation

### Precision Loss
- [ ] Division before multiplication avoided
- [ ] Rounding direction correct for protocol
- [ ] Sufficient decimals for calculations
- [ ] Consistent decimal handling across tokens

### Economic Calculations
- [ ] Interest rate calculations correct
- [ ] Fee calculations don't round to zero
- [ ] Share/asset conversions precise
- [ ] No first depositor inflation attack

---

## 4. Reentrancy

### External Calls
- [ ] Checks-Effects-Interactions pattern followed
- [ ] ReentrancyGuard used where needed
- [ ] Read-only reentrancy considered (Curve, etc.)
- [ ] Cross-function reentrancy checked

### Callback Safety
- [ ] ERC-777/ERC-1155 hooks handled
- [ ] Flash loan callbacks secured
- [ ] Native ETH receive() protected
- [ ] External protocol callbacks validated

---

## 5. Oracle Security

### Price Feeds
- [ ] Oracle source appropriate (Chainlink, TWAP, etc.)
- [ ] Staleness checks implemented
- [ ] Decimal normalization correct
- [ ] Fallback oracle configured

### Manipulation Resistance
- [ ] No spot price usage for value-sensitive ops
- [ ] TWAP window sufficient (>30 min)
- [ ] Flash loan manipulation considered
- [ ] Read-only reentrancy on price reads checked

### L2-Specific
- [ ] Sequencer uptime checked (Arbitrum, Optimism)
- [ ] Grace period after sequencer recovery

---

## 6. Token Handling

### ERC-20 Compatibility
- [ ] Using SafeERC20 for transfers
- [ ] Fee-on-transfer tokens handled
- [ ] Rebasing tokens handled correctly
- [ ] Non-standard return values handled (USDT, BNB)

### Special Token Types
- [ ] Blacklist-able tokens considered (USDC, USDT)
- [ ] Pausable tokens considered
- [ ] Upgradeable tokens considered
- [ ] Flash-mintable tokens considered

### Approvals
- [ ] No unlimited approvals to untrusted contracts
- [ ] Approval race condition handled
- [ ] Permit (EIP-2612) properly validated

---

## 7. State Management

### Storage
- [ ] Storage layout correct (especially upgrades)
- [ ] No uninitialized storage pointers
- [ ] Proper delete for mappings/arrays
- [ ] No storage collision in proxy patterns

### Memory
- [ ] Large data structures handled efficiently
- [ ] Memory arrays properly bounded
- [ ] Return data properly handled

### Events
- [ ] All state changes emit events
- [ ] Event parameters correct
- [ ] No sensitive data in events
- [ ] Indexed parameters appropriate

---

## 8. External Interactions

### Contract Calls
- [ ] Return values checked
- [ ] Reverts handled appropriately
- [ ] Low-level calls validated
- [ ] Delegate calls restricted

### Protocol Integration
- [ ] External protocol assumptions documented
- [ ] Admin action risks assessed
- [ ] Upgrade risks considered
- [ ] Pause/fail scenarios handled

### Cross-Chain
- [ ] Message verification correct
- [ ] Replay attacks prevented
- [ ] Finality assumptions appropriate

---

## 9. Economic Security

### Flash Loan Attacks
- [ ] No spot price manipulation vectors
- [ ] Invariants hold within single transaction
- [ ] Multi-block attack vectors considered

### MEV Risks
- [ ] Sandwich attack protection (slippage limits)
- [ ] Frontrunning sensitive operations protected
- [ ] Deadline parameters enforced

### Incentive Alignment
- [ ] Liquidation incentives appropriate
- [ ] No griefing vectors
- [ ] Protocol fees can't be gamed

---

## 10. Upgrade Safety

### Proxy Patterns
- [ ] Initialization properly restricted
- [ ] Storage layout preserved on upgrade
- [ ] Upgrade process uses timelock
- [ ] No selfdestruct in implementation

### Migration
- [ ] Migration path clearly documented
- [ ] User funds protected during migration
- [ ] No loss of state during migration

---

## 11. Edge Cases

### Boundary Conditions
- [ ] Zero amounts handled
- [ ] First/last user scenarios
- [ ] Empty arrays handled
- [ ] Max values handled (type(uint256).max)

### State Transitions
- [ ] Invalid state transitions prevented
- [ ] Race conditions in state transitions
- [ ] Concurrent operations handled

### Time-Based
- [ ] Block timestamp manipulation considered
- [ ] Deadline handling correct
- [ ] Interest accrual timing attacks

---

## 12. Gas Optimization Concerns

### DoS Vectors
- [ ] No unbounded loops on user-controlled data
- [ ] No high gas costs blocking critical operations
- [ ] Batch operations bounded

### Griefing
- [ ] No cheap griefing attacks
- [ ] Spam prevention mechanisms
- [ ] Dust attacks prevented

---

## 13. Documentation & Code Quality

### Code
- [ ] NatSpec comments complete
- [ ] Complex logic explained
- [ ] No dead code
- [ ] Consistent naming conventions

### Documentation
- [ ] Architecture documented
- [ ] Trust assumptions stated
- [ ] Risk factors disclosed
- [ ] Upgrade process documented

---

## Severity Classification Guide

### Critical
- Direct fund theft possible
- Protocol insolvency
- Permanent fund lock

### High
- Significant fund loss (>1% TVL)
- Privilege escalation
- Core functionality broken

### Medium
- Limited fund loss
- Temporary DoS
- Incorrect state possible
- Governance attacks

### Low
- Minor issues
- Best practice violations
- Gas inefficiencies with security implications

### Informational
- Code style
- Documentation
- Gas optimizations

---

*Last Updated: 2026-02-03*
