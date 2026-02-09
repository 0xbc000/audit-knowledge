# Lending Protocol Audit Checklist

Specialized checklist for auditing lending protocols (Compound-style, AAVE-style, isolated lending).

---

## Protocol Understanding

Before auditing, understand:
- [ ] What's the lending model (pool-based, isolated, p2p)?
- [ ] What assets can be supplied/borrowed?
- [ ] What's the liquidation mechanism?
- [ ] What's the interest rate model?

---

## 1. Supply/Deposit Security

### Share Calculation
- [ ] Supply share calculation correct
- [ ] No first depositor inflation attack
- [ ] Exchange rate manipulation prevented
- [ ] Rounding direction favors protocol

**Check Pattern:**
```solidity
// First depositor protection
if (totalSupply == 0) {
    shares = amount - MINIMUM_SHARES;
    _mint(address(0), MINIMUM_SHARES);
}
```

### Asset Handling
- [ ] Fee-on-transfer tokens handled
- [ ] Rebasing tokens handled (if supported)
- [ ] Correct token transferred
- [ ] Amount received validated

### Supply Caps
- [ ] Supply caps enforced correctly
- [ ] Cap checks happen before transfer
- [ ] Edge cases at cap boundary

---

## 2. Borrow Security

### Borrow Limits
- [ ] Borrowing doesn't exceed collateral value × LTV
- [ ] Borrow caps enforced
- [ ] Health factor check after borrow
- [ ] Can't borrow more than available liquidity

### Borrow Rate
- [ ] Interest rate calculation correct
- [ ] Rate changes don't cause issues
- [ ] Utilization rate manipulation resistance

**From AAVE v3.3:**
```solidity
// CHECK: Rate manipulation via flash loan
// Can attacker spike utilization to harm borrowers?
// Are there rate caps?
```

### Debt Accounting
- [ ] Debt correctly accrues interest
- [ ] Debt token balance reflects total owed
- [ ] No debt manipulation via transfers

---

## 3. Repayment Security

### Repayment Accounting
- [ ] Repayment reduces debt correctly
- [ ] Interest paid before principal (if designed so)
- [ ] Full repayment possible
- [ ] Overpayment handled correctly

### On-Behalf-Of
- [ ] Repaying for others works correctly
- [ ] No griefing via forced repayment
- [ ] Allowance checked for on-behalf-of

---

## 4. Withdrawal Security

### Withdrawal Limits
- [ ] Can only withdraw if health factor stays above 1
- [ ] Can't withdraw more than deposited
- [ ] Utilization after withdrawal checked

### Share Redemption
- [ ] Shares correctly burned
- [ ] Exchange rate at redemption time used
- [ ] No manipulation of redemption rate

---

## 5. Liquidation Security

### Liquidation Conditions
- [ ] Liquidation only when health factor < 1
- [ ] Health factor calculation correct
- [ ] Liquidation threshold vs LTV appropriate

### Liquidation Execution
- [ ] Correct collateral seized
- [ ] Correct debt repaid
- [ ] Liquidation bonus correct
- [ ] Partial liquidation (close factor) works

### Liquidation Economics
**From AAVE v3.3:**
- [ ] Liquidation incentive sufficient
- [ ] No dust position griefing
- [ ] Bad debt handled correctly

```solidity
// CHECK: Dust position attack
// Can attacker create tiny positions that cost more to liquidate?
// Is there minimum collateral requirement?
```

### Self-Liquidation
- [ ] Define if self-liquidation is allowed
- [ ] If not allowed, properly prevented

---

## 6. Oracle Integration

### Price Feeds
- [ ] Chainlink integration correct (see oracle-manipulation.md)
- [ ] Staleness checks implemented
- [ ] Decimal handling correct
- [ ] L2 sequencer status checked

### Collateral Valuation
- [ ] All collateral types have oracles
- [ ] Oracle manipulation resistance verified
- [ ] No spot price for valuation

### Debt Valuation
- [ ] Borrowed asset prices correct
- [ ] Price feed for debt repayment
- [ ] Stablecoin depeg handling

---

## 7. Interest Rate Model

### Rate Calculation
- [ ] Utilization rate formula correct
- [ ] Borrow rate calculation correct
- [ ] Supply rate calculation correct
- [ ] Spread (reserve factor) applied correctly

### Rate Bounds
- [ ] Maximum rate capped
- [ ] Minimum rate (if applicable)
- [ ] Kink point works correctly
- [ ] Rate model can be updated safely

### Interest Accrual
**From AAVE v3.3:**
- [ ] Interest accrues atomically
- [ ] No timing attack on interest

```solidity
// CHECK: Interest accrual timing attack
// Can attacker exploit time between balance read and burn?
// Is accrueInterest() called before operations?
```

---

## 8. Collateral Management

### Collateral Types
- [ ] Collateral factor appropriate for each asset
- [ ] Correlation between collateral types considered
- [ ] Aggregate exposure limits

### Collateral Operations
- [ ] Enabling/disabling collateral works
- [ ] Collateral status change checks health factor
- [ ] Cross-collateral calculations correct

### Isolation Mode (if applicable)
**From AAVE v3.3:**
- [ ] Isolated assets properly restricted
- [ ] Can't escape isolation mode unexpectedly
- [ ] Debt ceiling for isolated assets

```solidity
// CHECK: Isolation mode bypass
// Can user move isolated collateral to non-isolated mode?
// Are edge cases in mode transition handled?
```

---

## 9. Bad Debt Handling

### Detection
- [ ] Underwater positions detected
- [ ] Bad debt quantified correctly
- [ ] Reporting mechanism exists

### Resolution
**From AAVE v3.3:**
- [ ] Bad debt clearing mechanism exists
- [ ] Interest rate updated correctly when clearing bad debt
- [ ] Socialization or insurance fund mechanism

```solidity
// CHECK: Bad debt accounting
// Does burning debt token without transfer cause issues?
// Is interest rate calculated on correct base?
```

---

## 10. Configuration Security

### Parameter Validation
**From AAVE v3.3:**
- [ ] No contradictory configurations allowed
- [ ] Valid parameter ranges enforced
- [ ] Configuration changes don't break existing positions

```solidity
// CHECK: Configuration inconsistency
// Can borrowable=true but borrowCap=0?
// This creates confusing/broken state
```

### Parameter Changes
- [ ] Timelock on sensitive changes
- [ ] Existing positions protected from sudden changes
- [ ] Liquidation threshold changes handled

---

## 11. Access Control

### User Functions
- [ ] Only owner can withdraw their funds
- [ ] Delegation properly implemented
- [ ] No unauthorized operations

### Admin Functions
**From AAVE v3.3:**
- [ ] All admin functions access-controlled
- [ ] Library functions not accidentally exposed
- [ ] Multi-sig for critical operations

```solidity
// CHECK: Library access control
// Are library functions properly internal?
// Can library be called directly via delegatecall?
```

---

## 12. Reserve Management

### Protocol Reserve
- [ ] Reserve factor collected correctly
- [ ] Reserve withdrawal only by authorized
- [ ] Reserve can't be drained

### Reserve Usage
- [ ] Reserve available for bad debt coverage
- [ ] Reserve withdrawal doesn't harm protocol

---

## 13. Flash Loans

### Flash Loan Security
- [ ] Flash loan fee correct
- [ ] Reentrancy during flash loan handled
- [ ] State consistency after flash loan
- [ ] Can't exploit protocol via flash loan

### Flash Loan Callbacks
- [ ] Callback validation
- [ ] No arbitrary code execution
- [ ] State changes properly ordered

---

## 14. Cross-Chain (if applicable)

### Message Handling
**From AAVE v3.3:**
- [ ] Cross-chain messages validated
- [ ] Message delay doesn't create exploits
- [ ] Chain-specific token behavior handled

```solidity
// CHECK: Chain-specific behavior
// Does WETH behave same on all chains?
// Are there chain-specific edge cases?
```

---

## 15. Upgrade Safety

### Proxy Pattern
- [ ] Storage layout preserved
- [ ] Initialization only once
- [ ] Upgrade requires timelock

### Migration
- [ ] User positions preserved
- [ ] Interest accrued correctly during migration
- [ ] No fund loss during upgrade

---

## Common Lending Protocol Vulnerabilities Summary

| Vulnerability | AAVE Reference | Mitigation |
|--------------|----------------|------------|
| Interest timing attack | v3.3 finding | Accrue before operations |
| Bad debt accounting | v3.3 finding | Track bad debt separately |
| Dust position griefing | v3.3 finding | Minimum collateral |
| Configuration inconsistency | v3.3 finding | Validate config states |
| Library access control | v3.3 finding | Internal visibility |
| Cross-chain differences | v3.3 finding | Chain-specific handling |
| Unbounded iteration DoS | v3.3 finding | Limit reserves per user |
| Silent permit bypass | v3.3 finding | Check permit return |

---

*Based on: AAVE v3.3 Sherlock findings, Compound audits, Euler exploit analysis*
*Last Updated: 2026-02-03*
