# DEX/AMM Vulnerability Patterns

Protocol types: Uniswap-style AMMs, Curve, Balancer, concentrated liquidity, order books

## 1. Price Manipulation Attacks

### 1.1 Spot Price Manipulation
**Description:** Using spot price from pool reserves instead of TWAP/oracle
**Attack Vector:**
1. Flash loan large amount
2. Swap to skew reserves
3. Trigger vulnerable protocol action using manipulated spot price
4. Reverse swap and repay

**Detection Pattern:**
```solidity
// VULNERABLE: Direct reserve ratio
uint256 price = reserveA / reserveB;

// SAFER: Use TWAP or external oracle
uint256 price = oracle.getPrice();
```

**Real Examples:**
- Harvest Finance ($34M) - Curve pool manipulation
- Cheese Bank ($3.3M) - Price oracle manipulation

### 1.2 TWAP Manipulation
**Description:** Multi-block price manipulation to affect TWAP
**Attack Vector:**
1. Manipulate price at end of block N
2. Hold position through block N+1
3. TWAP now reflects manipulated price

**Detection Pattern:**
- Short TWAP windows (< 30 minutes) are vulnerable
- Check if protocol uses `observe()` with short intervals

---

## 2. Liquidity Provider Attacks

### 2.1 Just-In-Time (JIT) Liquidity
**Description:** Add LP position right before large swap, remove immediately after
**Attack Vector:**
1. Monitor mempool for large swaps
2. Front-run with concentrated liquidity add at exact price
3. Collect most of swap fees
4. Back-run to remove liquidity

**Impact:** Existing LPs earn less fees

### 2.2 Sandwich Attacks
**Description:** Front-run and back-run user swaps
**Detection Pattern:**
```solidity
// VULNERABLE: No slippage protection
function swap(uint256 amountIn) {
    // No minAmountOut parameter
}

// SAFER: Enforce slippage
function swap(uint256 amountIn, uint256 minAmountOut) {
    require(amountOut >= minAmountOut, "Slippage");
}
```

### 2.3 LP Token Inflation Attack
**Description:** Donate tokens to inflate LP token value
**Attack Vector:**
1. Be first depositor
2. Deposit minimal amount
3. Donate large amount directly to pool
4. LP token value per share massively inflated
5. Subsequent depositors lose to rounding

**Detection Pattern:**
```solidity
// VULNERABLE: No minimum liquidity
function addLiquidity(uint256 amount) {
    shares = amount * totalSupply / totalAssets;
}

// SAFER: Burn minimum liquidity
if (totalSupply == 0) {
    _mint(address(0), MINIMUM_LIQUIDITY);
}
```

---

## 3. Curve-Specific Vulnerabilities

### 3.1 Read-Only Reentrancy
**Description:** Curve's `remove_liquidity()` updates balances before callback
**Attack Vector:**
1. Call `remove_liquidity()` on Curve pool
2. In ETH receive callback, pool state is inconsistent
3. Call external protocol that reads Curve's virtual price
4. Virtual price is stale/manipulated during callback

**Detection Pattern:**
```solidity
// VULNERABLE: Reading Curve state synchronously
uint256 price = curvePool.get_virtual_price();

// SAFER: Use oracle with reentrancy guard
uint256 price = curveOracle.lp_price();
```

**Real Examples:**
- Multiple DeFi protocols exploited via this vector

### 3.2 LP Token Valuation Assumptions
**Description:** Assuming fixed LP token value
**From Napier 015-H:**
```solidity
// VULNERABLE: Assumes 1 BaseLpt = 3 PT always
// This only holds at initial balanced deposit
uint256 value = lpAmount * 3;

// SAFER: Query actual pool state
uint256 value = curvePool.calc_withdraw_one_coin(lpAmount, ptIndex);
```

---

## 4. Concentrated Liquidity Risks

### 4.1 Tick Crossing Manipulation
**Description:** Forcing price across ticks to trigger state changes
**Attack Vector:**
1. Large swap pushes price across multiple ticks
2. Each tick crossing updates liquidity accounting
3. Rounding errors accumulate
4. Protocol reading stale tick state makes wrong decisions

### 4.2 Position NFT Risks
**Description:** LP positions as NFTs introduce transfer-related risks
**Detection Pattern:**
- What happens when position NFT is transferred during pending rewards?
- Can attacker claim rewards then transfer to avoid penalties?
- Are positions properly removed from tracking on transfer?

### 4.3 Out-of-Range Positions
**Description:** Positions that are no longer in active range
**Detection Pattern:**
- How are out-of-range positions handled?
- Can fees still be collected?
- What happens to incentives/rewards?

---

## 5. Order Book DEX Vulnerabilities

### 5.1 Front-Running Orders
**Description:** See limit order, front-run with market order
**Detection Pattern:**
- Is there on-chain order visibility before execution?
- Are there mechanisms to prevent front-running (commit-reveal)?

### 5.2 Order Griefing
**Description:** Repeatedly placing/canceling orders to waste gas
**Detection Pattern:**
- Is there a cost to place/cancel orders?
- Can attacker fill orders with dust amounts?

---

## 6. DEX Aggregator Risks

### 6.1 Callback Exploitation
**Description:** Malicious callback during swap execution
**Detection Pattern:**
```solidity
// VULNERABLE: Arbitrary external call
function executeSwap(address router, bytes calldata data) {
    router.call(data); // Can call anything
}

// SAFER: Whitelist routers and validate
require(whitelistedRouters[router], "Invalid router");
```

### 6.2 Token Approval Draining
**Description:** User approves aggregator, attacker drains via malicious route
**Detection Pattern:**
- Are token approvals limited to exact swap amounts?
- Can route data specify arbitrary token transfers?

---

## 7. Protocol-Specific Edge Cases

### 7.1 Pool Creation/Initialization
**Detection Questions:**
- [ ] Can anyone create pools?
- [ ] Can malicious pools be created with same token pair?
- [ ] Is there first depositor protection?
- [ ] Can pool parameters be set to extreme values?

### 7.2 Fee Handling
**Detection Questions:**
- [ ] Are fees collected atomically or accumulated?
- [ ] Can fee collection be front-run?
- [ ] What happens to protocol fees if admin address is compromised?

### 7.3 Token Compatibility
**Detection Questions:**
- [ ] How are fee-on-transfer tokens handled?
- [ ] How are rebasing tokens handled?
- [ ] What about tokens with non-standard decimals?
- [ ] Tokens that return false instead of reverting?

---

## Audit Checklist

### Price Oracle
- [ ] Does protocol use spot price? → HIGH RISK
- [ ] TWAP window length adequate? (>30 min recommended)
- [ ] Is virtual price used during potential reentrancy?

### Liquidity Mechanics
- [ ] First depositor attack protection?
- [ ] Minimum liquidity burned?
- [ ] LP share calculation rounding direction correct?

### Slippage Protection
- [ ] All swaps have minAmountOut?
- [ ] Deadline parameter enforced?
- [ ] Slippage protection in multi-hop swaps?

### External Calls
- [ ] Callback functions validated?
- [ ] Reentrancy guards in place?
- [ ] Router addresses whitelisted?

---

*Sources: Code4rena DEX audits, Uniswap security docs, Trail of Bits reports*
*Last Updated: 2026-02-03*
