# Liquidation & Clearance Risk Patterns

Vulnerabilities in liquidation mechanisms across lending, perpetuals, and collateralized protocols.

---

## 1. Liquidation Economics

### 1.1 Insufficient Liquidation Incentive
**Description:** Liquidator profit too low to cover gas + risk
**Attack Vector:**
1. Position becomes underwater
2. Liquidation incentive (e.g., 5%) insufficient
3. No one liquidates (gas costs, MEV competition)
4. Protocol accumulates bad debt

**Detection Pattern:**
```solidity
// VULNERABLE: Fixed small incentive
uint256 liquidatorBonus = collateralAmount * 5 / 100; // 5% flat

// SAFER: Dynamic incentive based on position health
uint256 liquidatorBonus = calculateDynamicIncentive(
    collateralAmount,
    debtAmount,
    healthFactor
);
```

### 1.2 Excessive Liquidation Penalty
**Description:** Penalty so high it drains user unfairly
**Attack Vector:**
1. User slightly underwater (e.g., 99% health)
2. 15% liquidation penalty applied
3. User loses much more than necessary
4. Creates adversarial behavior (griefing liquidations)

### 1.3 Partial vs Full Liquidation
**Description:** Inefficient partial liquidation mechanics
**Detection Pattern:**
- Can liquidator choose to partially liquidate?
- Is there minimum liquidation amount?
- Can many small liquidations grief a position?

---

## 2. Liquidation Timing Attacks

### 2.1 Oracle-Based Frontrunning
**Description:** Front-run oracle update that triggers liquidation
**Attack Vector:**
1. See oracle update tx in mempool
2. Price drop will make position liquidatable
3. Front-run with liquidation tx using current price
4. Oracle updates, position now shows as liquidated

**Detection Pattern:**
```solidity
// VULNERABLE: Instant liquidation on price change
function liquidate(address user) {
    uint256 price = oracle.getPrice(); // Can be front-run
    require(isLiquidatable(user, price));
    executeLiquidation(user);
}

// SAFER: Use committed price with delay
function liquidate(address user) {
    uint256 price = oracle.getCommittedPrice(); // Already finalized
    require(isLiquidatable(user, price));
}
```

### 2.2 Block-Stuff Liquidation
**Description:** Attacker fills blocks to delay liquidation
**Attack Vector:**
1. Attacker's position is liquidatable
2. Stuff blocks with high-gas txs
3. Liquidator txs can't get in
4. Wait for favorable price movement
5. Position no longer liquidatable

### 2.3 Time-Delayed Liquidation
**Description:** Exploit time between liquidation trigger and execution
**Detection Pattern:**
- Is there a grace period?
- Can attacker add collateral during grace period?
- What happens to accrued interest during grace period?

---

## 3. Liquidation Cascade

### 3.1 Mass Liquidation Events
**Description:** Multiple liquidations cause price spiral
**Attack Vector:**
1. Large price drop
2. Many positions become liquidatable
3. Liquidators sell collateral on market
4. Selling pressure drops price further
5. More positions liquidatable → cascade

**Detection Pattern:**
- Is there liquidation rate limiting?
- How is collateral sold (market vs auction)?
- Are there circuit breakers?

### 3.2 Correlated Collateral Risk
**Description:** Many positions use same correlated collateral
**Example:**
- stETH used as collateral
- stETH depegs
- All stETH-collateralized positions liquidatable simultaneously

**Detection Pattern:**
- Are there caps on single collateral type?
- Is correlation between collateral types tracked?

### 3.3 Systemic Risk Amplification
**Description:** Protocol liquidations affect broader DeFi
**Detection Pattern:**
- What's the TVL relative to collateral's market cap?
- Could mass liquidation significantly move collateral price?
- Are there integrations that would cascade?

---

## 4. Bad Debt Mechanisms

### 4.1 Bad Debt Accumulation
**Description:** Underwater positions create bad debt
**From AAVE v3.3 Analysis:**
```solidity
// VULNERABLE: Burns debt without accounting
function clearBadDebt(address user) {
    uint256 debt = getDebt(user);
    debtToken.burn(user, debt);
    // Debt gone but collateral insufficient to cover
    // Interest rate now calculated on wrong base
}

// SAFER: Track bad debt separately
function clearBadDebt(address user) {
    uint256 debt = getDebt(user);
    totalBadDebt += debt;
    debtToken.burn(user, debt);
    updateInterestRateWithBadDebt();
}
```

### 4.2 Bad Debt Socialization
**Description:** How bad debt is distributed
**Options:**
1. **Lender Socialization:** All lenders share loss
2. **Insurance Fund:** Protocol fund covers
3. **Token Holder:** Governance token used
4. **No Mechanism:** Protocol becomes insolvent

**Detection Pattern:**
- Is there an insurance fund?
- How large is the fund relative to TVL?
- What's the bad debt handling mechanism?

### 4.3 Dust Position Attack
**From AAVE v3.3:**
```solidity
// VULNERABLE: No minimum position size
// Attacker creates many tiny collateral positions
// Cost to liquidate > value recovered
// Bad debt accumulates from dust positions

// SAFER: Minimum position size
require(collateralAmount >= MIN_COLLATERAL, "Position too small");
```

---

## 5. Liquidation MEV

### 5.1 Liquidation Auction Competition
**Description:** MEV bots compete for liquidations
**Impact:**
- Liquidators may pay high gas, reducing net incentive
- Failed liquidation txs waste gas
- Small liquidators priced out

### 5.2 Sandwich Liquidation
**Description:** Sandwich the liquidation sale
**Attack Vector:**
1. See liquidation tx that will sell collateral
2. Front-run: Buy collateral asset
3. Liquidation executes, sells collateral (pushes price down)
4. Back-run: Sell at higher price

### 5.3 Just-In-Time Liquidation
**Description:** Wait until last moment to liquidate
**Attack Vector:**
1. Monitor underwater positions
2. Wait until interest accrual makes liquidation maximally profitable
3. Front-run other liquidators at precise moment

---

## 6. Collateral-Specific Risks

### 6.1 Illiquid Collateral Liquidation
**Description:** Collateral can't be sold quickly
**Detection Pattern:**
- What's the on-chain liquidity for collateral?
- Can liquidated collateral be swapped atomically?
- Is there slippage protection in liquidation?

### 6.2 Yield-Bearing Collateral
**Description:** Collateral accrues yield, affecting liquidation
**Detection Pattern:**
- How is yield-bearing collateral valued?
- Can yield be harvested during liquidation?
- Is there a delay between yield accrual and value update?

### 6.3 NFT Collateral Risks
**Description:** NFT collateral has unique liquidation challenges
**Detection Pattern:**
- How are NFTs valued for liquidation?
- What if no one bids on the NFT?
- How long can NFT liquidation take?

---

## 7. Protocol-Specific Patterns

### 7.1 Lending Protocol Liquidation
**Key Checks:**
- [ ] Health factor calculation correct?
- [ ] Liquidation threshold vs LTV ratio appropriate?
- [ ] Close factor reasonable (partial liquidation)?
- [ ] Liquidation incentive sufficient?

### 7.2 Perpetual Protocol Liquidation
**Key Checks:**
- [ ] Mark price vs index price used correctly?
- [ ] Funding rate affects liquidation threshold?
- [ ] Insurance fund covers gaps?
- [ ] ADL (auto-deleveraging) mechanism fair?

### 7.3 CDP/Stablecoin Liquidation
**Key Checks:**
- [ ] Auction mechanism manipulation-resistant?
- [ ] Minimum bid requirements?
- [ ] What if no bidders (keeper of last resort)?
- [ ] Global settlement mechanism?

---

## 8. Edge Cases

### 8.1 Self-Liquidation
**Description:** Borrower liquidates themselves
**Detection Pattern:**
```solidity
// VULNERABLE: Anyone can liquidate
function liquidate(address borrower, address liquidator) {
    // Borrower can call with liquidator = self
    // Captures liquidation bonus
}

// May or may not be desired behavior
```

### 8.2 Flashloan-Assisted Liquidation
**Description:** Liquidator uses flash loan to liquidate
**Detection Pattern:**
- Can liquidation be done in single tx with flash loan?
- Does this create new attack vectors?
- Is this profitable for small liquidators?

### 8.3 Liquidation During Extreme Volatility
**Description:** Liquidation fails during market crash
**Detection Pattern:**
- What if all liquidators are busy?
- What if gas prices spike during crash?
- What if oracle is delayed during crash?

### 8.4 Zero Collateral Value
**Description:** Collateral becomes worthless
**Detection Pattern:**
- What if collateral price goes to 0?
- How is division by zero handled?
- What's the protocol response to worthless collateral?

---

## 9. Liquidation Bypasses

### 9.1 Borrowing Against Liquidation
**Description:** Borrow more to avoid liquidation temporarily
**Attack Vector:**
1. Position at 90% health
2. Borrow more against same collateral
3. Use borrowed funds to pay down debt
4. Temporarily healthy but more levered

### 9.2 Collateral Swap
**Description:** Swap to higher-factor collateral before liquidation
**Detection Pattern:**
- Can collateral be swapped atomically?
- Does swap temporarily make position unhealthy?
- Are there reentrancy concerns during swap?

### 9.3 Front-Running Health Factor Updates
**Description:** Act before health factor recalculation
**Attack Vector:**
1. Know that interest accrual will make position liquidatable
2. Act before accrual function is called
3. Avoid liquidation by removing collateral or closing position

---

## Audit Checklist

### Liquidation Economics
- [ ] Incentive covers gas + MEV risk?
- [ ] Penalty appropriate for position health?
- [ ] Partial liquidation mechanics clear?

### Timing
- [ ] Oracle frontrunning prevented?
- [ ] Grace period appropriate?
- [ ] No block-stuffing vulnerability?

### Cascade Prevention
- [ ] Rate limiting on liquidations?
- [ ] Correlated collateral tracked?
- [ ] Circuit breakers present?

### Bad Debt
- [ ] Bad debt handling mechanism exists?
- [ ] Insurance fund adequately sized?
- [ ] Dust positions prevented?

### Edge Cases
- [ ] Self-liquidation handled?
- [ ] Extreme volatility scenario considered?
- [ ] Zero collateral value handled?

---

*Sources: AAVE v3.3 findings, Compound audits, MakerDAO Black Thursday analysis*
*Last Updated: 2026-02-03*
