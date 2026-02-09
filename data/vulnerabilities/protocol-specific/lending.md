# Lending Protocol Vulnerability Patterns

Protocol types: Compound-style, AAVE, isolated lending, RWA lending

## 1. Liquidation Vulnerabilities

### 1.1 Liquidation Frontrunning
**Description:** Liquidators front-run each other, or borrowers front-run liquidation
**Attack Vectors:**
1. **Liquidator Sandwich:** See liquidation tx, front-run to liquidate first
2. **Borrower Self-Liquidation:** Borrower liquidates self to avoid penalty
3. **Oracle Frontrunning:** See oracle update that makes position liquidatable, position before update

**Detection Pattern:**
```solidity
// VULNERABLE: Uses pending oracle price
uint256 price = oracle.getPrice(); // Can be front-run

// SAFER: Use committed oracle with delay
uint256 price = oracle.getCommittedPrice();
```

### 1.2 Bad Debt Socialization
**Description:** Underwater positions leave bad debt for other lenders
**From AAVE v3.3 Analysis:**
```solidity
// VULNERABLE: Burns debt token without actual token transfer
function liquidateBadDebt(address user) {
    uint256 debt = debtToken.balanceOf(user);
    debtToken.burn(user, debt);
    // No actual token transfer - interest rate updates incorrectly
}

// SAFER: Account for bad debt separately
badDebtTotal += debt;
updateInterestRateWithBadDebt();
```

### 1.3 Dust Position Griefing
**Description:** Create tiny collateral positions to block liquidation
**From AAVE v3.3:**
```solidity
// VULNERABLE: Liquidation requires profitable amount
// Attacker creates positions with 1 wei collateral
// Costs more gas to liquidate than value recovered
// Bad debt accumulates

// SAFER: Minimum position sizes
require(collateralAmount >= MIN_COLLATERAL);
```

### 1.4 Liquidation Cascade
**Description:** Mass liquidations cause price spiral
**Detection Pattern:**
- What happens if multiple large positions liquidate simultaneously?
- Is there rate limiting on liquidations?
- Can liquidated collateral sales cause further liquidations?

---

## 2. Interest Rate Manipulation

### 2.1 Interest Accrual Timing Attacks
**From AAVE v3.3:**
```solidity
// VULNERABLE: Balance read before interest accrual
uint256 balance = token.balanceOf(user); // Stale
// ... other operations ...
token.burn(user, balance); // Interest accrued in between

// SAFER: Force accrual first
accrueInterest();
uint256 balance = token.balanceOf(user);
```

### 2.2 Utilization Rate Manipulation
**Description:** Borrow/repay to manipulate interest rates
**Attack Vector:**
1. Flash loan to borrow maximum from pool
2. Utilization rate spikes to 100%
3. Interest rate jumps to maximum
4. Other borrowers forced to pay high interest
5. Repay flash loan

**Detection Pattern:**
- Is there max rate cap?
- Are there borrowing limits per block?
- How quickly can utilization change?

### 2.3 Reserve Factor Exploitation
**Description:** Manipulate timing of reserve factor collection
**Detection Pattern:**
- When is reserve factor collected?
- Can collection be forced at favorable times?
- Are reserves subject to same interest model?

---

## 3. Collateral Manipulation

### 3.1 Collateral Factor Gaming
**Description:** Exploit differences in collateral factors
**Attack Vector:**
1. Deposit high-factor collateral
2. Borrow maximum
3. Collateral price drops
4. Position underwater faster due to high leverage

**Detection Pattern:**
- Are collateral factors appropriate for asset volatility?
- Are there aggregate exposure limits per collateral type?

### 3.2 Rebasing Collateral Issues
**Description:** Collateral balance changes without transfers
**Detection Pattern:**
```solidity
// VULNERABLE: Caches balance
uint256 collateral = balanceOf[user];
// ... rebasing happens externally ...
// collateral is now stale

// SAFER: Always read fresh balance
uint256 collateral = token.balanceOf(address(this));
```

**Examples:**
- stETH, aTokens, cTokens as collateral

### 3.3 Cross-Collateral Risk
**Description:** Risk from multiple collateral types
**Detection Pattern:**
- How is aggregate risk calculated?
- Can user have both safe and risky collateral?
- Is correlated collateral (e.g., ETH derivatives) properly weighted?

---

## 4. Oracle Vulnerabilities

### 4.1 Stale Price Exploitation
**Description:** Use outdated oracle prices for favorable trades
**Detection Pattern:**
```solidity
// VULNERABLE: No freshness check
(, int256 price, , , ) = priceFeed.latestRoundData();

// SAFER: Check freshness
(, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt < MAX_DELAY);
```

### 4.2 Oracle Manipulation via Flash Loan
**Description:** Manipulate on-chain oracle price
**Detection Pattern:**
- Does oracle use spot price?
- Can price be moved significantly in single transaction?
- Is there TWAP or other manipulation resistance?

### 4.3 Multi-Oracle Inconsistency
**Description:** Different oracles report different prices
**Detection Pattern:**
- What happens if primary oracle fails?
- How is fallback oracle selected?
- Can attacker arbitrage between oracle prices?

---

## 5. Configuration Vulnerabilities

### 5.1 Inconsistent Configuration States
**From AAVE v3.3:**
```solidity
// VULNERABLE: Contradictory config allowed
asset.borrowable = true;
asset.borrowCap = 0; // Effectively not borrowable

// Users/integrators expect borrowable=true to work
// But 0 cap blocks all borrows
```

### 5.2 Parameter Manipulation
**Description:** Admin changes parameters at unfavorable time
**Detection Pattern:**
- Is there timelock on parameter changes?
- Can liquidation threshold be lowered instantly?
- What happens to existing positions on parameter change?

### 5.3 Asset Listing Risks
**Description:** New asset listing with incorrect parameters
**Detection Pattern:**
- Who can list new assets?
- Are there minimum requirements for listed assets?
- Can malicious token contract be listed?

---

## 6. Cross-Chain Lending Risks

### 6.1 Message Delay Exploitation
**Description:** Cross-chain health factor becomes stale
**Attack Vector:**
1. User has collateral on Chain A, borrow on Chain B
2. Bridge message delayed
3. User's action on Chain A not reflected on Chain B
4. Can double-spend or avoid liquidation

### 6.2 Chain-Specific Token Behavior
**From AAVE v3.3:**
```solidity
// VULNERABLE: Assumes same behavior across chains
// WETH on mainnet behaves differently than on L2s
// Some chains use custom WETH implementations
```

---

## 7. Siloed/Isolated Lending Risks

### 7.1 Isolation Mode Bypass
**Description:** Escaping isolation mode restrictions
**Detection Pattern:**
- Can isolated collateral be moved to non-isolated mode?
- Are there edge cases in isolation mode transitions?
- What happens to existing borrows on mode change?

### 7.2 Siloed Borrowing Griefing
**Description:** Forcing user into siloed mode against their will
**Detection Pattern:**
- Can attacker dust-deposit siloed collateral for victim?
- Are there recovery mechanisms from siloed state?

---

## 8. Library/Proxy Vulnerabilities

### 8.1 Library Access Control
**From AAVE v3.3:**
```solidity
// VULNERABLE: Library function without access control
library PoolLogic {
    function executeWithdraw(...) internal {
        // No access control in library
        // Relies on calling contract to check
    }
}

// If library is accidentally exposed or called directly
// Access control is bypassed
```

### 8.2 Upgrade Compatibility
**Description:** Upgrade breaks existing position accounting
**Detection Pattern:**
- Are storage slots preserved on upgrade?
- How are in-flight transactions handled?
- Is there upgrade pause mechanism?

---

## Audit Checklist

### Liquidation Mechanics
- [ ] Can liquidation be front-run?
- [ ] Is bad debt properly handled?
- [ ] Are dust positions prevented?
- [ ] Is there liquidation rate limiting?

### Interest Rate
- [ ] Are interest accruals atomic?
- [ ] Can utilization be manipulated?
- [ ] Are rate caps in place?

### Collateral
- [ ] Proper handling of rebasing tokens?
- [ ] Appropriate collateral factors?
- [ ] Cross-collateral risk managed?

### Oracle
- [ ] Freshness checks on prices?
- [ ] Manipulation-resistant (TWAP, etc.)?
- [ ] Fallback oracle configured?

### Configuration
- [ ] Timelock on sensitive params?
- [ ] No contradictory config states?
- [ ] Asset listing properly gated?

---

*Sources: AAVE v3.3 Sherlock findings, Compound audits, Euler exploit analysis*
*Last Updated: 2026-02-03*
