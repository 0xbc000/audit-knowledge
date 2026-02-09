# Uniswap V3 Integration Vulnerability Patterns

> **Source:** Revert Lend Benchmark (H-05), Multiple DEX Audits
> **Priority:** HIGH - Common integration mistakes with concentrated liquidity

---

## Overview

Uniswap V3 introduced concentrated liquidity with complex math. Protocols integrating V3 often make mistakes in:
- TWAP oracle calculations
- Tick math and rounding
- Position value calculations
- Liquidity math

---

## 1. TWAP Tick Rounding Error

### Pattern Description
When calculating TWAP from `tickCumulatives`, negative tick deltas require rounding DOWN, not truncation. Solidity's integer division truncates toward zero, which rounds UP for negative numbers.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: Wrong rounding for negative ticks
function _getTwapTick(address pool, uint32 twapSeconds) internal view returns (int24 tick) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapSeconds;
    secondsAgos[1] = 0;
    
    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    
    // BUG: This truncates toward zero, not down!
    tick = int24(tickCumulativesDelta / int56(int32(twapSeconds)));
}
```

### Correct Implementation (from Uniswap OracleLibrary)
```solidity
function _getTwapTick(address pool, uint32 twapSeconds) internal view returns (int24 tick) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapSeconds;
    secondsAgos[1] = 0;
    
    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    
    tick = int24(tickCumulativesDelta / int56(int32(twapSeconds)));
    
    // CRITICAL: Round towards negative infinity for negative deltas
    if (tickCumulativesDelta < 0 && (tickCumulativesDelta % int56(int32(twapSeconds)) != 0)) {
        tick--;
    }
}
```

### Why It Matters
- Price = 1.0001^tick
- Wrong tick by 1 = ~0.01% price error
- For large positions, this causes significant value miscalculation
- Can be exploited for:
  - Understating collateral value in lending
  - Manipulating oracle prices
  - Gaming liquidation thresholds

### Detection Questions
- Does the protocol calculate TWAP from `tickCumulatives`?
- Is there negative tick handling?
- Compare implementation with canonical `OracleLibrary.consult()`
- What's the impact of 1 tick error on protocol logic?

### Real Examples
- **Revert Lend H-05:** `_getReferencePoolPriceX96()` shows incorrect price for negative tick deltas

---

## 2. Tick Spacing Violations

### Pattern Description
Uniswap V3 enforces tick spacing (1, 10, 60, or 200 depending on fee tier). Calculations that don't account for this produce invalid ticks.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: May produce invalid tick
function calculateNewTick(int24 baseTick, int24 offset) public pure returns (int24) {
    return baseTick + offset;  // May not be valid tick for pool's spacing
}
```

### Correct Implementation
```solidity
function calculateNewTick(
    int24 baseTick, 
    int24 offset, 
    int24 tickSpacing
) public pure returns (int24) {
    int24 rawTick = baseTick + offset;
    // Round down to nearest valid tick
    return (rawTick / tickSpacing) * tickSpacing;
}
```

### Detection Questions
- Are calculated ticks always valid for the pool's spacing?
- Is tick spacing propagated correctly through calculations?
- What happens if invalid tick is passed to V3 functions?

---

## 3. Price Calculation Precision Loss

### Pattern Description
Converting between ticks and prices (sqrtPriceX96) involves significant precision considerations.

### Vulnerable Code Patterns
```solidity
// VULNERABLE: Precision loss in price calculation
function getPrice(int24 tick) public pure returns (uint256 price) {
    // This can overflow or lose precision
    price = uint256(1.0001e18) ** uint256(int256(tick));
}

// VULNERABLE: Wrong order of operations
function calculateValue(uint160 sqrtPriceX96, uint128 liquidity) public pure returns (uint256) {
    // Division before multiplication = precision loss
    uint256 price = (sqrtPriceX96 / 2**96) ** 2;
    return liquidity * price;
}
```

### Correct Implementation
```solidity
// Use Uniswap's TickMath and FullMath libraries
import "@uniswap/v3-core/contracts/libraries/TickMath.sol";
import "@uniswap/v3-core/contracts/libraries/FullMath.sol";

function getPrice(int24 tick) public pure returns (uint160 sqrtPriceX96) {
    sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
}

function calculateValue(uint160 sqrtPriceX96, uint128 liquidity) public pure returns (uint256) {
    // Proper full precision multiplication
    return FullMath.mulDiv(
        uint256(sqrtPriceX96) * uint256(sqrtPriceX96),
        liquidity,
        2**192
    );
}
```

### Detection Questions
- Does the protocol use canonical Uniswap math libraries?
- Are there custom price/tick calculations?
- Is FullMath used for large number multiplication?
- What's the precision loss at extreme ticks (near MIN_TICK/MAX_TICK)?

---

## 4. Position Value Miscalculation

### Pattern Description
Calculating the value of a Uniswap V3 LP position requires accounting for:
- Current tick vs position range
- Amount of each token based on current price
- Uncollected fees

### Vulnerable Code Patterns
```solidity
// VULNERABLE: Assumes 50/50 split
function getPositionValue(uint256 tokenId) public view returns (uint256) {
    (,,,, int24 tickLower, int24 tickUpper,,,,,) = nftManager.positions(tokenId);
    uint256 totalLiquidity = getLiquidity(tokenId);
    // WRONG: Position may be 100% in one token
    return totalLiquidity * getPrice() / 1e18;
}

// VULNERABLE: Ignores position being out of range
function calculateCollateral(uint256 tokenId) public view returns (uint256) {
    uint128 liquidity = getLiquidity(tokenId);
    uint160 sqrtPrice = getSqrtPrice();
    // If current tick outside range, one amount is 0
    return calculateAmount0(liquidity, sqrtPrice) + calculateAmount1(liquidity, sqrtPrice);
}
```

### Correct Implementation
```solidity
function getPositionValue(uint256 tokenId) public view returns (uint256 value0, uint256 value1) {
    (,, address token0, address token1, int24 tickLower, int24 tickUpper, 
     uint128 liquidity,,,,) = nftManager.positions(tokenId);
    
    (, int24 currentTick,,,,,) = pool.slot0();
    uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(currentTick);
    uint160 sqrtPriceLower = TickMath.getSqrtRatioAtTick(tickLower);
    uint160 sqrtPriceUpper = TickMath.getSqrtRatioAtTick(tickUpper);
    
    if (currentTick < tickLower) {
        // Position entirely in token0
        value0 = LiquidityAmounts.getAmount0ForLiquidity(sqrtPriceLower, sqrtPriceUpper, liquidity);
        value1 = 0;
    } else if (currentTick >= tickUpper) {
        // Position entirely in token1
        value0 = 0;
        value1 = LiquidityAmounts.getAmount1ForLiquidity(sqrtPriceLower, sqrtPriceUpper, liquidity);
    } else {
        // Position in range - has both tokens
        value0 = LiquidityAmounts.getAmount0ForLiquidity(sqrtPriceX96, sqrtPriceUpper, liquidity);
        value1 = LiquidityAmounts.getAmount1ForLiquidity(sqrtPriceLower, sqrtPriceX96, liquidity);
    }
}
```

---

## 5. Observation Cardinality Issues

### Pattern Description
TWAP reliability depends on oracle observation array having sufficient history. Low cardinality = easier manipulation.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: No cardinality check
function getReliableTwap(address pool, uint32 period) public view returns (int24) {
    // If cardinality is low, this TWAP may be easily manipulated
    return OracleLibrary.consult(pool, period);
}
```

### Correct Implementation
```solidity
function getReliableTwap(address pool, uint32 period) public view returns (int24 tick) {
    (,,, uint16 observationCardinality, uint16 observationCardinalityNext,,) = 
        IUniswapV3Pool(pool).slot0();
    
    // Require sufficient observations
    require(observationCardinality >= period / 60, "Insufficient oracle history");
    
    // Also check age of oldest observation
    (uint32 oldestTimestamp,,,) = IUniswapV3Pool(pool).observations(
        (observationCardinality + 1) % observationCardinality
    );
    require(block.timestamp - oldestTimestamp >= period, "Oracle history too short");
    
    tick = OracleLibrary.consult(pool, period);
}
```

### Detection Questions
- Does the protocol verify observation cardinality?
- What's the minimum TWAP period used?
- Can an attacker expand cardinality then manipulate?
- Is there protection against stale oracle data?

---

## 6. Flash Loan + TWAP Manipulation

### Pattern Description
While TWAP is more resistant than spot price, multi-block attacks can still manipulate it, especially for short periods.

### Attack Vectors
1. **Low liquidity pools:** Easier to move price significantly
2. **Short TWAP periods:** Less averaging = easier manipulation
3. **Multi-block attacks:** Maintain position across blocks
4. **Just-in-time liquidity:** Add/remove liquidity around target block

### Detection Questions
- What TWAP period is used? (< 30 min is risky)
- What's the liquidity depth of the pool?
- Are there secondary price checks?
- Is there circuit breaker for large price moves?

### Mitigation Patterns
```solidity
// Multiple oracle sources
function getPrice() internal view returns (uint256) {
    uint256 twapPrice = getTwapPrice();
    uint256 chainlinkPrice = getChainlinkPrice();
    
    // Check deviation
    uint256 deviation = twapPrice > chainlinkPrice 
        ? (twapPrice - chainlinkPrice) * 10000 / chainlinkPrice
        : (chainlinkPrice - twapPrice) * 10000 / chainlinkPrice;
    
    require(deviation < 300, "Price deviation too high");  // 3%
    
    return twapPrice;
}
```

---

## 7. Liquidity Concentration Attacks

### Pattern Description
V3's concentrated liquidity means LP positions can be highly directional. This affects:
- Collateral valuation (position may be 100% in losing token)
- Impermanent loss calculation
- Range order execution

### Vulnerable Assumptions
```solidity
// VULNERABLE: Assumes position has value in both tokens
function getMinValue(uint256 tokenId) public view returns (uint256) {
    (uint256 amount0, uint256 amount1) = getPositionAmounts(tokenId);
    // If position out of range, one of these is 0!
    return min(amount0 * price0, amount1 * price1);
}
```

### Detection Questions
- Does collateral valuation handle out-of-range positions?
- What happens to LTV when position goes out of range?
- Can users create extreme range positions for manipulation?

---

## Checklist: Uniswap V3 Integration Audit

### Oracle/TWAP
- [ ] Is negative tick rounding handled correctly?
- [ ] Is observation cardinality verified?
- [ ] What TWAP period is used? (min 30 min recommended)
- [ ] Is there multi-oracle validation?
- [ ] How are stale observations handled?

### Math/Precision
- [ ] Are canonical Uniswap libraries used?
- [ ] Is FullMath used for large multiplications?
- [ ] Are tick spacing constraints enforced?
- [ ] Is there precision loss at extreme ticks?

### Position Valuation
- [ ] Are out-of-range positions handled correctly?
- [ ] Is uncollected fee accounting correct?
- [ ] Is liquidity-to-value conversion correct?
- [ ] Are both tokens valued appropriately?

### Edge Cases
- [ ] What happens at MIN_TICK/MAX_TICK?
- [ ] What happens with 0 liquidity?
- [ ] What happens with single-sided positions?
- [ ] Are fee tier differences handled?

---

## Code Patterns to Flag

```solidity
// 1. TWAP without negative rounding
tick = tickCumulativesDelta / period;  // BUG: needs rounding fix

// 2. Direct tick comparison without spacing
if (tick == targetTick)  // May never be true if spacing != 1

// 3. Position value without range check
value = amount0 + amount1 * price;  // One may be 0

// 4. sqrtPriceX96 without proper scaling
price = sqrtPriceX96 * sqrtPriceX96;  // Overflow risk

// 5. No cardinality check before TWAP
OracleLibrary.consult(pool, period);  // May be manipulable
```

---

*Last Updated: 2026-02-04*
*Source: Revert Lend Benchmark Analysis, Uniswap V3 Documentation*
