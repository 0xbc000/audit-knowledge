# DEX/AMM Audit Checklist

Specialized checklist for auditing DEX and AMM protocols.

---

## Protocol Understanding

Before auditing, understand:
- [ ] What's the AMM model (constant product, stable, concentrated)?
- [ ] Who provides liquidity and how?
- [ ] What's the fee structure?
- [ ] Are there special features (limit orders, hooks, etc.)?

---

## 1. Pool Creation Security

### Pool Initialization
- [ ] Pool can only be initialized once
- [ ] Initial liquidity requirements met
- [ ] First LP attack prevented

**Check Pattern:**
```solidity
// First depositor protection
if (totalSupply == 0) {
    liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
    _mint(address(0), MINIMUM_LIQUIDITY);
}
```

### Pool Parameters
- [ ] Fee parameters validated
- [ ] Tick spacing valid (if concentrated)
- [ ] No malicious pool creation

### Token Pair Validation
- [ ] Same token can't be paired with itself
- [ ] Token addresses validated
- [ ] Token ordering consistent

---

## 2. Liquidity Provision

### LP Token Minting
- [ ] LP shares correctly calculated
- [ ] Proportional minting for existing pools
- [ ] No inflation attack possible
- [ ] Rounding favors existing LPs

### Single-Sided Liquidity
- [ ] Imbalanced deposits handled correctly
- [ ] Impermanent loss properly accounted
- [ ] Slippage protection for single-sided

### Concentrated Liquidity (if applicable)
- [ ] Position ranges correctly tracked
- [ ] Tick boundary handling correct
- [ ] Out-of-range position handling
- [ ] Position NFT security

---

## 3. Swap Security

### Price Calculation
- [ ] Swap amounts correctly calculated
- [ ] Constant product/invariant maintained
- [ ] Fee deduction correct
- [ ] No price manipulation in single tx

### Slippage Protection
- [ ] `minAmountOut` enforced
- [ ] Deadline parameter checked
- [ ] Multi-hop slippage accumulated correctly

```solidity
// CHECK: Slippage protection
require(amountOut >= minAmountOut, "Slippage");
require(block.timestamp <= deadline, "Expired");
```

### Price Impact
- [ ] Large swaps have appropriate impact
- [ ] No free swap possible
- [ ] Reserves update correctly

---

## 4. Fee Handling

### Fee Collection
- [ ] Fees correctly deducted from swaps
- [ ] Fee goes to correct recipients
- [ ] Protocol fee vs LP fee split correct

### Fee Distribution
- [ ] LP fee proportional to liquidity
- [ ] Fee compounding correct (if applicable)
- [ ] No fee theft between LPs

### Dynamic Fees (if applicable)
- [ ] Fee calculation formula correct
- [ ] Fee bounds enforced
- [ ] No fee manipulation attack

---

## 5. Oracle Security

### TWAP Oracle
- [ ] TWAP accumulator updated correctly
- [ ] TWAP window configurable and sufficient
- [ ] No manipulation of TWAP readings

**Check Pattern:**
```solidity
// TWAP window should be > 30 minutes for security
uint256 twapPrice = consult(token, 1800); // 30 min minimum
```

### Spot Price
- [ ] Spot price clearly documented as manipulable
- [ ] Warnings against using spot for valuation
- [ ] Alternative oracle provided/recommended

---

## 6. MEV Protection

### Sandwich Attack
- [ ] Documentation warns about sandwich risk
- [ ] Slippage parameters available
- [ ] Consider MEV-resistant features

### Just-In-Time (JIT) Liquidity
- [ ] Impact on regular LPs considered
- [ ] Mitigation strategies (if any)

### Frontrunning
- [ ] Critical operations protected
- [ ] Consider commit-reveal schemes
- [ ] Deadline parameters help

---

## 7. Router/Aggregator Security

### Router Validation
- [ ] Router properly validates swap paths
- [ ] No arbitrary external calls
- [ ] Token approvals limited

### Multi-Hop Swaps
- [ ] Intermediate tokens validated
- [ ] Cumulative slippage checked
- [ ] Gas limits for long paths

### Callback Security
- [ ] Callback caller validated
- [ ] Callback data validated
- [ ] No reentrancy via callback

---

## 8. Flash Swap/Loan

### Flash Swap Security
- [ ] Repayment enforced
- [ ] Fee correctly applied
- [ ] State consistent during flash swap

### Callback Reentrancy
- [ ] Reentrancy guard on relevant functions
- [ ] State changes before callback
- [ ] Callback can't manipulate pool state

---

## 9. Token Compatibility

### Standard Tokens
- [ ] ERC-20 compliance checked
- [ ] SafeERC20 used for transfers
- [ ] Return value handling

### Fee-on-Transfer Tokens
- [ ] Balance change measured, not amount
- [ ] Accounting handles fee deduction
- [ ] Documentation on supported tokens

### Rebasing Tokens
- [ ] Balance changes handled
- [ ] LP share calculation correct
- [ ] Consider disallowing rebasing tokens

### Non-Standard Decimals
- [ ] Different decimals handled
- [ ] Price calculations account for decimals
- [ ] Display vs internal precision

---

## 10. Pool Management

### Pool State
- [ ] Reserve tracking correct
- [ ] No reserve manipulation via donation
- [ ] Sync/skim functions correct (if exists)

### Emergency Functions
- [ ] Pause mechanism (if exists) appropriate
- [ ] Emergency withdrawal available
- [ ] Admin can't steal funds

### Pool Upgrades
- [ ] Upgrade mechanism secure
- [ ] LP positions preserved
- [ ] Timelock on upgrades

---

## 11. Curve-Specific (Stable Pools)

### Virtual Price
- [ ] Virtual price calculation correct
- [ ] Read-only reentrancy prevented
- [ ] Virtual price manipulation resistance

### Amplification Factor
- [ ] A parameter bounds checked
- [ ] A parameter change gradual
- [ ] Extreme A values handled

### Imbalanced Pools
- [ ] Extreme imbalance handling
- [ ] Withdrawal from imbalanced pool
- [ ] Fee adjustments for imbalance

---

## 12. Concentrated Liquidity Specific

### Tick Mechanics
- [ ] Tick initialization correct
- [ ] Tick crossing updates correct
- [ ] Boundary tick handling

### Position Management
- [ ] Position NFT minting/burning correct
- [ ] Fee collection per position correct
- [ ] Position range modifications

### Liquidity Bounds
- [ ] Max liquidity per tick enforced
- [ ] Global liquidity limits
- [ ] Price range limits

---

## 13. Access Control

### User Functions
- [ ] Only LP owner can remove liquidity
- [ ] Position ownership verified
- [ ] No unauthorized fee collection

### Admin Functions
- [ ] Fee changes gated
- [ ] Protocol fee withdrawal gated
- [ ] Pool parameter changes timelocked

---

## 14. Invariant Checks

### Core Invariants
- [ ] Constant product holds (or stable curve invariant)
- [ ] LP total supply = sum of positions
- [ ] Fees collected ≤ fees owed

### Reserve Invariants
- [ ] Reserve ≥ LP obligations
- [ ] No reserve drain possible
- [ ] Reserve-LP ratio maintained

---

## 15. Edge Cases

### Zero Amounts
- [ ] Zero swap handled
- [ ] Zero liquidity add/remove handled
- [ ] Division by zero prevented

### Empty Pool
- [ ] First deposit handling
- [ ] Last withdrawal handling
- [ ] Empty pool state recovery

### Extreme Values
- [ ] Max token amounts handled
- [ ] Price at extremes (near 0, near max)
- [ ] Liquidity at extremes

---

## Common DEX Vulnerabilities Summary

| Vulnerability | Category | Mitigation |
|--------------|----------|------------|
| First depositor attack | Initialization | Minimum liquidity burn |
| Sandwich attack | MEV | Slippage + deadline params |
| Price manipulation | Oracle | Use TWAP, not spot |
| Read-only reentrancy | Curve | Safe oracle implementations |
| LP token inflation | Accounting | Minimum shares, rounding |
| Fee theft | Fee handling | Per-position fee tracking |
| Router arbitrary calls | Integration | Whitelist and validation |
| Flash loan manipulation | Economic | Invariant checks |

---

*Based on: Uniswap V2/V3 audits, Curve audits, Code4rena DEX contests*
*Last Updated: 2026-02-03*
