# Yield Protocol Audit Checklist

Specialized checklist for auditing yield tokenization protocols (PT/YT, yield vaults, yield aggregators).

---

## Protocol Understanding

Before auditing, understand:
- [ ] What underlying asset generates yield?
- [ ] How is yield tokenized (PT/YT split, rebasing, etc.)?
- [ ] What's the maturity mechanism?
- [ ] Who are the actors (depositors, redeemers, liquidity providers)?

---

## 1. Principal Token (PT) Security

### Valuation
- [ ] PT valuation accounts for time-to-maturity
- [ ] PT price never exceeds underlying (pre-maturity)
- [ ] PT properly redeemable at 1:1 at maturity
- [ ] Early redemption mechanism correct (if exists)

### Accounting
- [ ] PT minting matches deposited underlying
- [ ] PT burning returns correct underlying amount
- [ ] No inflation attack on first PT mint
- [ ] PT total supply invariants maintained

### Maturity
- [ ] Post-maturity PT behavior correct
- [ ] No actions allowed that shouldn't work post-maturity
- [ ] Settlement mechanism handles all PT holders fairly

---

## 2. Yield Token (YT) Security

### Yield Distribution
- [ ] YT holders receive correct yield share
- [ ] Yield distribution timing fair
- [ ] No yield theft between YT holders
- [ ] Unclaimed yield properly tracked

**From Napier 005-H:**
```solidity
// CHECK: Zero-amount redemption
// Can calling redeemWithYT(from, to, 0) steal yield?
// Zero amount may bypass burn but still transfer yield
```

### Yield Calculation
- [ ] Yield accrual calculation correct
- [ ] No yield loss from rounding
- [ ] Frequent claims don't lose yield

**From Napier 021-M:**
```solidity
// CHECK: Frequent claim penalty
// Does frequent claiming result in less yield?
// Some protocols round down each claim
```

### Maturity Handling
- [ ] YT behavior at maturity defined
- [ ] YT value goes to zero at maturity (if designed so)
- [ ] Final yield distribution fair

---

## 3. Exchange Rate / Scale Security

### Scale Manipulation
**From Napier 016-H:**
- [ ] Initial scale/exchange rate can't be manipulated
- [ ] Max scale setting protected from inflation attack
- [ ] Scale decrease handled fairly

```solidity
// CHECK: Max scale manipulation
// Can attacker inflate max scale at initialization?
// This may lock "sunny day" conditions permanently
```

### Scale Decrease Race
**From Napier 012-H:**
- [ ] Scale decrease doesn't create race condition
- [ ] Early redeemers don't get unfair advantage
- [ ] Withdrawal queue or delay for fairness

```solidity
// CHECK: Redemption during scale decrease
// When scale decreases, who bears the loss?
// First-mover advantage = vulnerability
```

### Scale Sources
- [ ] External scale sources manipulation-resistant
- [ ] Scale update frequency appropriate
- [ ] Stale scale handling

---

## 4. Adapter Security

### Multi-Adapter Consistency
**From Napier 020-H:**
- [ ] Different adapters handle same logic consistently
- [ ] Token conversion correct in each adapter
- [ ] No adapter has missing functionality

```solidity
// CHECK: Adapter implementation consistency
// SFrxETH adapter has conversion, StETH doesn't
// Different adapters should handle similar underlying similarly
```

### Adapter Accounting
- [ ] Adapter total assets calculation correct
- [ ] Adapter handles rebasing underlying correctly
- [ ] Adapter yield reporting accurate

### Adapter External Calls
- [ ] External protocol calls handled correctly
- [ ] Adapter pause handling
- [ ] Adapter failure graceful degradation

---

## 5. AMM/Pool Integration

### LP Token Valuation
**From Napier 015-H:**
- [ ] LP token value correctly calculated
- [ ] No hardcoded LP token ratios

```solidity
// VULNERABLE: Assumes fixed ratio
// "1 BaseLpt = 3 PT" only true at initial balanced deposit
uint256 value = lpAmount * 3;

// SAFER: Query actual value
uint256 value = pool.calc_withdraw_one_coin(lpAmount, PT_INDEX);
```

### AMM Invariants
- [ ] AMM invariant maintained during swaps
- [ ] No arbitrage against the protocol
- [ ] Fee calculations correct

### Tilt Mechanism (if applicable)
**From Napier 018-H:**
- [ ] Tilt mechanism fairly distributes value
- [ ] No gaming of tilt direction
- [ ] Documentation matches implementation

---

## 6. Sunny Day / Cloudy Day Logic

### Sunny Day (Positive Yield)
- [ ] Sunny day conditions correctly defined
- [ ] Surplus yield distribution fair
- [ ] PT/YT holder split correct

### Cloudy Day (Negative Yield)
- [ ] Cloudy day handling doesn't steal from PT holders
- [ ] YT holders properly bear downside
- [ ] No permanent loss of principal

### Transition Logic
- [ ] State transition between sunny/cloudy correct
- [ ] No manipulation of which state occurs
- [ ] Edge cases at boundary handled

---

## 7. External Integration Risks

### Underlying Protocol
**From Napier 017-M, 019-M:**
- [ ] Underlying protocol admin actions handled
- [ ] Fee changes in underlying handled
- [ ] Pause in underlying handled

### Oracle Dependencies
- [ ] Exchange rate oracle manipulation-resistant
- [ ] Staleness checks on external prices
- [ ] Fallback for oracle failure

### Composability
- [ ] Flash loan attacks considered
- [ ] Cross-protocol reentrancy checked
- [ ] Integration assumptions documented

---

## 8. User Fund Safety

### Deposits
- [ ] Deposit amount correctly tracked
- [ ] No fund loss on deposit
- [ ] First depositor attack prevented

### Redemptions
- [ ] Redemption returns correct amount
- [ ] Redemption before maturity handled
- [ ] Redemption after maturity handled
- [ ] Partial redemption correct

### Withdrawals
- [ ] Withdrawal delay fair
- [ ] Buffer/queue manipulation prevented
- [ ] Stuck funds recoverable

**From Napier 014-H:**
```solidity
// CHECK: Buffer manipulation DoS
// Can attacker drain buffer to block withdrawals?
// Calculate exact deposit to exhaust buffer
```

---

## 9. Zero Amount Edge Cases

**From Napier 005-H, 008-M:**

### Zero Amount Operations
- [ ] `deposit(0)` handled correctly
- [ ] `redeem(0)` doesn't have side effects
- [ ] `claim(0)` doesn't steal yield
- [ ] `mint(0)` doesn't cause issues

```solidity
// CHECK: Zero amount bypass
// Does calling with amount=0 skip important checks?
// Are there side effects without main action?
```

---

## 10. Maturity Handling

### Pre-Maturity
- [ ] All pre-maturity functions work correctly
- [ ] No access to post-maturity-only functions
- [ ] Time-based calculations correct

### At Maturity
- [ ] Maturity transition atomic
- [ ] No race conditions at maturity
- [ ] All holders can redeem

### Post-Maturity
- [ ] PT redeemable 1:1 for underlying
- [ ] YT final yield distributed
- [ ] No lingering value in expired tokens

---

## 11. Economic Invariants

### Core Invariants
- [ ] PT + YT value = Underlying value
- [ ] Total claims ≤ Total assets
- [ ] No value creation from nothing
- [ ] No value destruction unexpectedly

### Accounting Invariants
- [ ] Sum of user balances = total supply
- [ ] Claimed yield + unclaimed yield = total yield
- [ ] Adapter assets = protocol's assets in adapter

---

## 12. Access Control

### User Actions
- [ ] Only owner can redeem their tokens
- [ ] Delegation properly implemented (if exists)
- [ ] No unauthorized yield claims

### Admin Actions
- [ ] Fee changes timelocked
- [ ] Pause mechanism appropriate
- [ ] No admin fund extraction

---

## Common Yield Protocol Vulnerabilities Summary

| Vulnerability | Napier Reference | Mitigation |
|--------------|------------------|------------|
| Scale manipulation at init | 016-H | Validate initial conditions |
| Scale decrease race | 012-H | Withdrawal queue/delay |
| Zero amount bypass | 005-H | Check amount > 0 where needed |
| Buffer manipulation DoS | 014-H | Buffer replenishment mechanism |
| LP token valuation error | 015-H | Dynamic valuation |
| Adapter inconsistency | 020-H | Standardize adapter implementations |
| Tilt mechanism gaming | 018-H | Clear documentation + validation |
| Frequent claim penalty | 021-M | Compound yield before claim |
| External admin actions | 017-M, 019-M | Graceful degradation |

---

*Based on: Napier Finance Sherlock findings, Pendle audits, Yield Protocol research*
*Last Updated: 2026-02-03*
