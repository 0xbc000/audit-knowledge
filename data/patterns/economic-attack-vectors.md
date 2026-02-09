# Economic Attack Vectors for Smart Contracts

Source: Compiled from 50+ real audit findings
Last Updated: 2026-02-03

These patterns focus on **economic attacks** that exploit incentive misalignments, market mechanics, and value extraction opportunities.

---

## 1. Flash Loan Amplified Attacks

### 1.1 Price Oracle Manipulation
**Pattern:** Spot prices used without TWAP protection

```solidity
// DANGEROUS: Direct spot price usage
uint256 price = IUniswapV2Pair(pair).price0CumulativeLast();
uint256 collateralValue = collateral * price;  // Can be manipulated
```

**Attack Flow:**
1. Flash loan massive token amount
2. Swap to manipulate spot price
3. Execute operation at manipulated price
4. Swap back, repay flash loan
5. Profit from price difference

**Detection Questions:**
- Does the protocol use spot prices?
- Is there TWAP protection? What's the window?
- Can flash loans manipulate the price source?

---

### 1.2 Virtual Balance Manipulation
**Pattern:** `balanceOf(address(this))` used for calculations

```solidity
// DANGEROUS: Balance can be inflated via direct transfer
uint256 totalAssets = token.balanceOf(address(this));
uint256 shares = (amount * totalSupply) / totalAssets;
```

**Attack Flow:**
1. Direct transfer tokens to inflate balance
2. Execute deposit at inflated rate
3. Get more shares than deserved
4. Withdraw with profit

---

## 2. Sandwich Attacks

### 2.1 AMM Swap Sandwiching
**Pattern:** Large swap without slippage protection

```solidity
// DANGEROUS: No minimum output enforced
router.swapExactTokensForTokens(
  amount, 
  0,  // <-- minAmountOut = 0!
  path, 
  msg.sender, 
  deadline
);
```

**Attack Flow:**
1. See victim's pending swap in mempool
2. Front-run with same-direction swap (raise price)
3. Victim's swap executes at worse price
4. Back-run with opposite swap (capture profit)

---

### 2.2 Liquidation Sandwiching
**Pattern:** Liquidations without competitive mechanisms

```solidity
// Profitable liquidation visible in mempool
function liquidate(address user) external {
  require(isLiquidatable(user));
  // Transfer collateral at discount
}
```

**Attack Flow:**
1. Monitor for liquidatable positions
2. Front-run legitimate liquidators
3. Extract MEV from discount

---

## 3. First Depositor/LP Attacks

### 3.1 Share Inflation Attack
**Pattern:** First depositor can manipulate share price

```solidity
// DANGEROUS: No minimum share amount
function deposit(uint256 assets) external returns (uint256 shares) {
  shares = totalSupply == 0 
    ? assets  // First depositor: 1 asset = 1 share
    : (assets * totalSupply) / totalAssets;
  // Attack: deposit 1 wei, donate 10000 tokens, ruin ratio
}
```

**Attack Flow:**
1. First depositor deposits minimal amount (1 wei)
2. Directly transfers large amount to vault
3. Next depositor gets 0 shares (rounded down)
4. First depositor withdraws everything

**Mitigation:** Require minimum first deposit, dead shares, or virtual offset

---

### 3.2 LP Token Ratio Manipulation
**Pattern:** Initial LP can set arbitrary token ratio

```solidity
// No constraints on initial ratio
function addLiquidity(uint256 amountA, uint256 amountB) external {
  if (totalSupply == 0) {
    lpTokens = sqrt(amountA * amountB);  // Any ratio accepted
  }
}
```

---

## 4. Arbitrage & MEV Extraction

### 4.1 Oracle Lag Exploitation
**Pattern:** Price updates lag behind market price

```solidity
// Oracle updates every N blocks/minutes
function getPrice() returns (uint256) {
  return latestAnswer;  // May be stale
}
```

**Attack Flow:**
1. Observe market price movement
2. Execute before oracle updates
3. Profit from price discrepancy

---

### 4.2 Cross-Protocol Arbitrage
**Pattern:** Price inconsistencies across protocols

```solidity
// Protocol A uses Chainlink, Protocol B uses Uniswap TWAP
// When prices diverge, arbitrage opportunity exists
```

---

## 5. Griefing Attacks (DoS for Profit)

### 5.1 Dust Griefing
**Pattern:** Small amounts block state transitions

```solidity
// Block liquidation by keeping dust collateral
if (userCollateral == 0) {
  processBadDebt();  // Only runs when zero
}
// Attack: keep 1 wei collateral forever
```

---

### 5.2 Gas Griefing
**Pattern:** Force victim into expensive operations

```solidity
// Attacker creates many small positions
// Victim must iterate through all of them
for (uint i = 0; i < positions.length; i++) {
  processPosition(positions[i]);
}
```

---

## 6. Interest Rate Manipulation

### 6.1 Utilization Rate Gaming
**Pattern:** Borrow/repay to manipulate rates

```solidity
// Interest rate depends on utilization
uint256 rate = baseRate + (utilization * slope);
// Attack: flash borrow to spike rate, harm other borrowers
```

---

### 6.2 Interest Accrual Gaming
**Pattern:** Timing attacks on interest updates

```solidity
// Interest compounds per block
// Attack: Large deposit right before interest accrual
// Withdraw immediately after to capture interest
```

---

## 7. Reward/Incentive Gaming

### 7.1 Just-In-Time Liquidity
**Pattern:** Add liquidity right before rewards distribute

```solidity
// Rewards distributed proportionally
// Attack: Add massive liquidity at last second
// Capture disproportionate rewards
```

---

### 7.2 Reward Token Recycling
**Pattern:** Claim rewards, reinvest, claim again

```solidity
// No cooldown between stake and reward eligibility
function stake(uint256 amount) external {
  balances[msg.sender] += amount;
  // Immediately eligible for next reward distribution
}
```

---

## Economic Attack Detection Checklist

For any DeFi protocol, systematically check:

### Price Manipulation
- [ ] What price sources are used? (Chainlink, Uniswap, custom)
- [ ] Is TWAP used? What's the window?
- [ ] Can flash loans manipulate the price?
- [ ] Is there a circuit breaker for large price moves?

### Value Extraction
- [ ] Are there sandwich-able operations?
- [ ] Is slippage protection enforced?
- [ ] Can MEV bots extract value?

### First Mover Advantage
- [ ] What happens with the first deposit?
- [ ] Can share price be manipulated before others deposit?
- [ ] Are there minimum amounts?

### Timing Attacks
- [ ] When do interest rates update?
- [ ] When do rewards distribute?
- [ ] Can timing be gamed for profit?

### Griefing Cost/Benefit
- [ ] What's the cost to grief someone?
- [ ] What's the victim's loss?
- [ ] Is there economic incentive for griefing?

---

## Prompt Enhancement for AI Auditors

When auditing any DeFi protocol, specifically check for:

```
1. Spot price usage without TWAP (flash loan vulnerable)
2. balanceOf(this) for calculations (donation attack)
3. First depositor with no minimum (inflation attack)
4. Swaps without slippage protection (sandwich attack)
5. Operations visible in mempool (front-running)
6. Interest rate manipulation via large borrow/repay
7. Reward distribution timing attacks
8. Dust amounts that block important operations
```
