# Oracle Manipulation Vulnerability Patterns

## Overview

Oracles are critical infrastructure for DeFi. Most high-value exploits involve oracle manipulation.

---

## 1. Flash Loan Oracle Attacks

### 1.1 Spot Price Manipulation
**Description:** Single-transaction manipulation of on-chain price
**Attack Vector:**
1. Flash loan large amount of token A
2. Swap A for B on DEX (pushes price)
3. Use manipulated price in vulnerable protocol
4. Profit from mispricing
5. Reverse swap and repay flash loan

**Detection Pattern:**
```solidity
// VULNERABLE: Using spot reserves
function getPrice() returns (uint256) {
    (uint256 reserveA, uint256 reserveB) = pool.getReserves();
    return reserveA / reserveB;
}

// SAFER: Use TWAP
function getPrice() returns (uint256) {
    return pool.consult(TOKEN, TWAP_PERIOD);
}
```

**Real Exploits:**
- Harvest Finance ($34M) - Curve price manipulation
- Warp Finance ($7.7M) - Uniswap LP price manipulation
- Cheese Bank ($3.3M) - Price oracle manipulation

### 1.2 TWAP Manipulation
**Description:** Multi-block manipulation to affect TWAP
**Attack Requirements:**
- Control price at end of block N
- Maintain control into block N+1
- Requires sustained capital (can't just flash loan)

**Detection Pattern:**
- TWAP window < 30 minutes → VULNERABLE
- TWAP window 30min-2hr → Medium risk
- TWAP window > 2hr → Lower risk but more stale

### 1.3 LP Token Price Manipulation
**Description:** Manipulating virtual price of LP tokens
**Attack Vector:**
1. Flash loan to skew pool reserves
2. LP token price calculation uses manipulated reserves
3. Borrow against inflated LP collateral
4. Exit position with profit

**Detection Pattern:**
```solidity
// VULNERABLE: Direct LP valuation
uint256 lpValue = lpToken.balanceOf(user) * virtualPrice;

// SAFER: Use fair LP pricing formula
uint256 lpValue = calculateFairLPValue(pool, lpAmount);
```

---

## 2. Chainlink Oracle Vulnerabilities

### 2.1 Stale Price Exploitation
**Description:** Using outdated oracle prices
**Detection Pattern:**
```solidity
// VULNERABLE: No freshness check
(, int256 price, , , ) = priceFeed.latestRoundData();
return uint256(price);

// SAFER: Full validation
(
    uint80 roundId,
    int256 price,
    ,
    uint256 updatedAt,
    uint80 answeredInRound
) = priceFeed.latestRoundData();

require(price > 0, "Negative price");
require(updatedAt != 0, "Round not complete");
require(answeredInRound >= roundId, "Stale price");
require(block.timestamp - updatedAt < MAX_STALENESS, "Price too old");

return uint256(price);
```

### 2.2 Round Completeness Issues
**Description:** Incomplete rounds reporting wrong data
**Detection Pattern:**
```solidity
// Check answeredInRound >= roundId
// If answeredInRound < roundId, round is incomplete
```

### 2.3 Price Feed Downtime
**Description:** Oracle not updating during volatility
**Attack Vector:**
1. Extreme market volatility
2. Oracle feed stops updating (gas prices, network issues)
3. Protocol uses stale price
4. Attacker arbitrages stale vs real price

**Detection Pattern:**
- Is there a fallback oracle?
- What happens if primary oracle is down?
- Are there circuit breakers?

### 2.4 Decimal Handling
**Description:** Incorrect decimal conversion
**Detection Pattern:**
```solidity
// VULNERABLE: Assuming 8 decimals
uint256 price = uint256(rawPrice) * 1e10; // Assumes 8 decimals

// SAFER: Query decimals
uint8 decimals = priceFeed.decimals();
uint256 price = uint256(rawPrice) * 10**(18 - decimals);
```

---

## 3. On-Chain Oracle Attacks

### 3.1 Read-Only Reentrancy
**Description:** Oracle read during inconsistent state
**Attack Vector (Curve):**
1. Call `remove_liquidity()` on Curve
2. In ETH callback, Curve state is inconsistent
3. Call protocol that reads Curve virtual price
4. Virtual price is manipulated

**Detection Pattern:**
```solidity
// VULNERABLE: Reading during potential reentrancy
function getCollateralValue(address pool) returns (uint256) {
    uint256 virtualPrice = ICurve(pool).get_virtual_price();
    return balance * virtualPrice;
}

// SAFER: Use reentrancy-resistant oracle
function getCollateralValue(address pool) returns (uint256) {
    uint256 virtualPrice = curveOracle.lp_price(); // Reentrancy-safe
    return balance * virtualPrice;
}
```

### 3.2 Donation Attack on Oracles
**Description:** Direct token donation affects oracle price
**Attack Vector:**
1. Protocol uses contract balance as oracle
2. Attacker donates tokens to inflate balance
3. Price appears higher
4. Borrow more against inflated collateral

**Detection Pattern:**
```solidity
// VULNERABLE: Using raw balance
function totalAssets() returns (uint256) {
    return token.balanceOf(address(this));
}

// SAFER: Track internal accounting
function totalAssets() returns (uint256) {
    return _trackedBalance;
}
```

### 3.3 Sandwich Oracle Updates
**Description:** Front-run and back-run oracle updates
**Attack Vector:**
1. See oracle update transaction in mempool
2. Front-run with position that profits from old price
3. Oracle updates
4. Close position at new price

---

## 4. Cross-Chain Oracle Risks

### 4.1 Message Delay Exploitation
**Description:** Cross-chain oracle updates are delayed
**Attack Vector:**
1. Price changes on source chain
2. Bridge/relay takes time to propagate
3. Arbitrage stale price on destination chain

### 4.2 Sequencer Downtime (L2s)
**Description:** L2 sequencer goes down, prices stale
**Detection Pattern:**
```solidity
// For L2s, check sequencer status
(, int256 answer, uint256 startedAt, , ) = sequencerFeed.latestRoundData();

bool isSequencerUp = answer == 0;
if (!isSequencerUp) {
    revert SequencerDown();
}

// Grace period after sequencer comes back up
if (block.timestamp - startedAt < GRACE_PERIOD) {
    revert GracePeriodNotOver();
}
```

### 4.3 Different Oracle Implementations
**Description:** Same asset has different oracles across chains
**Detection Pattern:**
- Are oracle addresses hardcoded for each chain?
- Do different chains have different staleness thresholds?
- Are decimal conversions chain-specific?

---

## 5. Multi-Oracle Systems

### 5.1 Oracle Disagreement
**Description:** Primary and fallback oracles report different prices
**Detection Pattern:**
```solidity
// VULNERABLE: Simple fallback
if (primaryPrice == 0) {
    return fallbackPrice;
}

// SAFER: Deviation check
if (abs(primaryPrice - fallbackPrice) / primaryPrice > MAX_DEVIATION) {
    revert OraclePriceDeviation();
}
```

### 5.2 Fallback Oracle Exploitation
**Description:** Attacker triggers fallback to more manipulable oracle
**Attack Vector:**
1. DoS primary oracle (if possible)
2. Protocol falls back to secondary oracle
3. Secondary oracle is easier to manipulate
4. Exploit manipulated price

### 5.3 Median Oracle Attacks
**Description:** Manipulating multiple sources to shift median
**Detection Pattern:**
- How many oracle sources?
- Cost to manipulate enough sources to shift median?
- Are sources independent?

---

## 6. Custom Oracle Vulnerabilities

### 6.1 Admin Oracle Manipulation
**Description:** Centralized oracle controlled by admin
**Detection Pattern:**
- Who can update oracle price?
- Is there timelock on price updates?
- What's the deviation limit per update?

### 6.2 Reporter Collusion
**Description:** Multiple reporters collude to manipulate price
**Detection Pattern:**
- How many reporters required?
- What's the economic stake?
- Are reporters decentralized?

### 6.3 Time-Weighted vs Spot Confusion
**Description:** Protocol expects TWAP but gets spot
**Detection Pattern:**
- Is oracle documented as TWAP or spot?
- Is the oracle interface clear about what it returns?
- Are there wrapper contracts that might change semantics?

---

## 7. Protocol-Specific Oracle Patterns

### 7.1 Lending Protocol Oracles
**Key Considerations:**
- Collateral valuation must be manipulation-resistant
- Liquidation triggers should use committed prices
- Bad debt from oracle manipulation can be socialized

### 7.2 DEX Protocol Oracles
**Key Considerations:**
- On-chain oracles are circular (DEX uses its own price)
- TWAP from low-liquidity pools is risky
- LP token pricing is complex

### 7.3 Derivatives Protocol Oracles
**Key Considerations:**
- Funding rate calculations sensitive to price
- Mark price vs index price
- Insurance fund drainage via oracle manipulation

---

## 8. Common Vulnerable Code Patterns

### 8.1 Missing Validation
```solidity
// VULNERABLE
int256 price = oracle.latestAnswer();
return uint256(price); // No checks!

// VULNERABLE
(, int256 price, , , ) = feed.latestRoundData();
return price; // Minimal checks
```

### 8.2 Incorrect Decimal Normalization
```solidity
// VULNERABLE: Wrong decimal assumption
uint256 priceInWei = uint256(price) * 1e10;

// VULNERABLE: Different token decimals not handled
uint256 value = amount * price / 1e8;
```

### 8.3 No Freshness Check
```solidity
// VULNERABLE: No timestamp check
uint256 price = oracle.getPrice();

// VULNERABLE: Insufficient staleness check
require(updatedAt > block.timestamp - 24 hours); // Too long!
```

---

## Audit Checklist

### Price Source
- [ ] What's the price source (Chainlink, TWAP, custom)?
- [ ] Is spot price used anywhere? → HIGH RISK
- [ ] Can price be manipulated in single tx?

### Chainlink-Specific
- [ ] Full `latestRoundData()` validation?
- [ ] Staleness threshold appropriate?
- [ ] L2 sequencer status checked?
- [ ] Decimal handling correct?

### On-Chain Oracle
- [ ] TWAP window long enough (>30 min)?
- [ ] Protected from read-only reentrancy?
- [ ] Donation attacks prevented?

### Multi-Oracle
- [ ] Fallback oracle configured?
- [ ] Deviation checks in place?
- [ ] All oracles equally secure?

### Integration
- [ ] Oracle appropriate for use case?
- [ ] Price freshness adequate for volatility?
- [ ] Circuit breakers present?

---

*Sources: Rekt News, DeFiHackLabs, Chainlink docs, Trail of Bits*
*Last Updated: 2026-02-03*
