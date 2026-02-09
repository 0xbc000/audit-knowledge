# MEV (Maximal Extractable Value) Attack Patterns

Comprehensive documentation of MEV attack vectors, real-world case studies, and smart contract defenses.

> **Last Updated:** 2026-02-06
> **Source:** Research from EigenPhi, Flashbots, academic papers, and real-world exploits

---

## Overview

MEV refers to the profit that can be extracted by miners/validators through their ability to arbitrarily include, exclude, or reorder transactions within blocks. In 2024-2025:
- **$561.92M** total MEV transaction volume (Flashbots data)
- **$289.76M (51.56%)** from sandwich attacks alone
- Average MEV revenue: **~$300,000/day** on Ethereum mainnet
- **$500M+** extracted from Solana users (Jan 2024 - May 2025) via sandwich bots

### L2 vs L1 MEV Landscape (New Research - Jan 2026)

Recent academic research (arXiv:2601.19570) reveals surprising findings about MEV on Layer 2 rollups:

| Environment | Sandwich Prevalence | Profitability | Attack Type |
|-------------|---------------------|---------------|-------------|
| **Ethereum L1** | Endemic | Profitable | Deterministic |
| **L2 (Private Mempool)** | Rare | Unprofitable | Probabilistic |

**Key Findings:**
- On L2s with private mempools, **median net return for sandwich attacks is negative**
- Without public mempool visibility, attackers must rely on sequencer ordering and redundant submissions
- **Majority of flagged sandwich patterns on L2s are false positives**
- Private mempools transform sandwiching from deterministic to probabilistic

**Implications for Auditors:**
- MEV severity ratings should differentiate between L1 and L2 deployments
- L2 protocols with private mempools have inherently lower sandwich risk
- Focus L2 MEV analysis on sequencer-related risks instead

---

## 1. Sandwich Attacks

### 1.1 Basic Sandwich Attack
**Description:** Front-running and back-running a victim's swap transaction

**Attack Flow:**
```
Block N:
  TX 1: Attacker buys token (front-run) - higher gas price
  TX 2: Victim's swap (target) - original gas price  
  TX 3: Attacker sells token (back-run) - lower gas price
```

**Detailed Mechanism:**
1. Searcher monitors mempool for large pending swaps
2. Identifies swap with significant price impact
3. Places buy order BEFORE victim (higher gas)
4. Victim's transaction executes at worse price (slippage)
5. Attacker sells immediately AFTER at inflated price

**Vulnerable Code Pattern:**
```solidity
// VULNERABLE: No slippage protection
function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
    uint256 amountOut = router.swapExactTokensForTokens(
        amountIn,
        0,              // ❌ No minimum output - 100% vulnerable
        path,
        msg.sender,
        block.timestamp
    );
}

// VULNERABLE: Excessive slippage tolerance
function swap(...) external {
    router.swapExactTokensForTokens(
        amountIn,
        amountIn * 80 / 100,  // ❌ 20% slippage - too high
        path,
        msg.sender,
        block.timestamp + 3600  // ❌ 1 hour deadline - too long
    );
}
```

**Secure Pattern:**
```solidity
// SAFE: Proper slippage protection
function swap(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,    // ✅ User-specified minimum
    uint256 deadline         // ✅ Short deadline
) external {
    require(block.timestamp <= deadline, "Expired");
    
    uint256 amountOut = router.swapExactTokensForTokens(
        amountIn,
        minAmountOut,         // ✅ Slippage protection
        path,
        msg.sender,
        deadline
    );
}

// SAFER: Use private mempool (Flashbots Protect)
// Submit transactions directly to block builders
// Bypasses public mempool visibility
```

### 1.2 Multi-Hop Sandwich
**Description:** Sandwiching across multiple DEX hops

**Attack Vector:**
1. Victim swaps A → B → C (multi-hop route)
2. Attacker sandwiches at each hop
3. Profit accumulates from each leg

**Detection Pattern:**
```solidity
// Check for multi-hop paths without per-hop slippage
function swapMultiHop(address[] calldata path, uint256 amountIn) {
    // ❌ Only checks final output, not intermediate hops
    require(finalAmount >= minAmountOut);
}
```

### 1.3 Cross-DEX Sandwich
**Description:** Sandwich using price differences across DEXs

**Attack Vector:**
1. Victim trades on DEX A
2. Attacker front-runs on DEX A
3. Attacker arbitrages price difference to DEX B
4. Compound profit from sandwich + arbitrage

---

## 2. Just-In-Time (JIT) Liquidity Attacks

### 2.1 Uniswap V3 JIT Attack
**Description:** Exploiting concentrated liquidity by providing liquidity just for one trade

**Attack Flow:**
```
Same Block:
  TX 1: Attacker mints concentrated liquidity in narrow tick range
  TX 2: Victim's large swap executes against attacker's liquidity
  TX 3: Attacker removes liquidity with fees earned
```

**Detailed Mechanism:**
1. Searcher detects large pending swap in mempool
2. Calculates the exact tick range the swap will traverse
3. Mints MASSIVE liquidity in that narrow range (often 1 tick)
4. Victim's swap executes almost entirely against attacker's position
5. Attacker captures majority of trading fees
6. Attacker burns position immediately after

**Impact:**
- Passive LPs have their fee share diluted (up to 90%+ dilution)
- Attacker earns fees with near-zero impermanent loss risk
- Liquidity only exists for a single block

**Vulnerable Conditions:**
```solidity
// Protocols allowing atomic mint/swap/burn are vulnerable
// Check if these can be called in same transaction:
- position.mint()
- pool.swap()
- position.burn()
- position.collect()
```

**Statistics (2025):**
- ~8-10% of large Uniswap V3 swaps are JIT-targeted
- JIT bots dominated by few sophisticated operators
- Average dilution for passive LPs: 15-40% on attacked swaps

### 2.2 Protocol-Level JIT Defenses

**Lockup Period Pattern:**
```solidity
// Defense: Require minimum liquidity duration
mapping(uint256 => uint256) public positionMintTime;

function mint(...) external returns (uint256 tokenId) {
    tokenId = _mint(...);
    positionMintTime[tokenId] = block.timestamp;
}

function burn(uint256 tokenId) external {
    require(
        block.timestamp >= positionMintTime[tokenId] + MIN_LIQUIDITY_PERIOD,
        "Liquidity locked"
    );
    _burn(tokenId);
}
```

**Fee Delay Pattern:**
```solidity
// Defense: Delay fee claiming
function collect(uint256 tokenId) external returns (uint256 fees) {
    require(
        block.timestamp >= positionMintTime[tokenId] + FEE_CLAIM_DELAY,
        "Fees not yet claimable"
    );
    fees = _collect(tokenId);
}
```

---

## 3. Oracle Manipulation via MEV

### 3.1 Flash Loan + Oracle Manipulation
**Description:** Using flash loans to manipulate spot prices used as oracles

**Attack Flow:**
```
Single Transaction:
  1. Flash loan large amount of Token A
  2. Swap Token A → Token B on target DEX (manipulates spot price)
  3. Interact with victim protocol using manipulated price
  4. Profit from incorrect valuation
  5. Reverse swap and repay flash loan
```

**Vulnerable Oracle Pattern:**
```solidity
// VULNERABLE: Using spot price directly
function getPrice() external view returns (uint256) {
    (uint256 reserve0, uint256 reserve1,) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;  // ❌ Spot price - manipulable
}

// VULNERABLE: Short TWAP window
function getPrice() external view returns (uint256) {
    return getTWAP(300);  // ❌ 5 minute TWAP - too short for high value
}
```

**Secure Oracle Pattern:**
```solidity
// SAFER: Long TWAP with multiple sources
function getPrice() external view returns (uint256) {
    uint256 twapPrice = getTWAP(1800);  // 30 minute TWAP
    uint256 chainlinkPrice = chainlinkOracle.latestAnswer();
    
    // Require prices within 5% of each other
    uint256 diff = twapPrice > chainlinkPrice 
        ? twapPrice - chainlinkPrice 
        : chainlinkPrice - twapPrice;
    require(diff * 100 / chainlinkPrice <= 5, "Price deviation");
    
    return chainlinkPrice;  // Use decentralized oracle as primary
}
```

### 3.2 TWAP Manipulation (Multi-Block)
**Description:** Manipulating TWAP oracles over multiple blocks

**Attack Conditions:**
1. Low liquidity pools
2. Short TWAP windows (< 30 minutes)
3. Attacker controls block production (e.g., via Flashbots bundles)

**Vulnerable Scenarios:**
```solidity
// VULNERABLE: TWAP on low liquidity pool
uint32 twapWindow = 10 minutes;
uint256 price = oracle.consult(lowLiquidityPool, twapWindow);
// Attacker can manipulate with ~$100k across 10 blocks

// SAFER: Require minimum liquidity
require(pool.liquidity() >= MIN_LIQUIDITY, "Insufficient liquidity");
uint32 twapWindow = 30 minutes;  // Longer window
```

### 3.3 Tick Rounding Exploitation (Uniswap V3)
**Description:** Exploiting tick math rounding in TWAP calculations

**Vulnerability:**
```solidity
// Uniswap V3 TWAP returns arithmetic mean of ticks
// Conversion: price = 1.0001^tick
// Arithmetic mean of ticks ≠ geometric mean of prices

// Attack: Asymmetric price movements cause TWAP drift
// If tick goes +100 then -100, TWAP shows net change due to rounding
```

**Detection Pattern:**
- Check for tick rounding in TWAP consumers
- Verify TWAP window is sufficient for pool's volatility
- Check observation cardinality is adequate

---

## 4. Liquidation MEV

### 4.1 Liquidation Front-Running
**Description:** Front-running oracle updates to execute liquidations

**Attack Flow:**
```
1. See oracle price update in mempool
2. New price will make position liquidatable
3. Submit liquidation TX with higher gas (front-run)
4. Capture liquidation bonus before others
```

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Uses latest price immediately
function liquidate(address user) external {
    uint256 price = oracle.getPrice();  // ❌ Can be front-run
    require(getHealthFactor(user, price) < 1e18, "Not liquidatable");
    _liquidate(user);
}
```

**Defense Pattern:**
```solidity
// SAFER: Use committed/finalized prices
function liquidate(address user) external {
    uint256 price = oracle.getCommittedPrice();  // Already on-chain
    // Or use time-delayed oracle with minimum age
    require(oracle.priceAge() >= MIN_PRICE_AGE, "Price too fresh");
}
```

### 4.2 Block-Stuffing to Avoid Liquidation
**Description:** Filling blocks with spam transactions to prevent liquidation

**Attack Flow:**
```
1. Attacker's position becomes liquidatable
2. Attacker spams high-gas transactions to fill blocks
3. Legitimate liquidation TXs cannot be included
4. Price recovers, position no longer liquidatable
```

**Detection:**
- Monitor for addresses with underwater positions + high TX volume
- Look for gas spike patterns around liquidation thresholds

**Defense Pattern:**
```solidity
// Add grace period that still accrues interest
function liquidate(address user) external {
    // Even if delayed, interest continues accruing
    _accrueInterest(user);
    
    // Use block number to prevent repeated stuffing
    require(
        block.number > lastLiquidationAttempt[user] + GRACE_BLOCKS,
        "Liquidation cooldown"
    );
}
```

### 4.3 Self-Liquidation MEV
**Description:** User liquidating themselves to capture bonus

**Attack Flow:**
```
1. User's position approaches liquidation threshold
2. User self-liquidates via proxy contract
3. Captures liquidation bonus instead of third party
4. Effective lower cost than waiting for external liquidation
```

**Detection Pattern:**
```solidity
// Check if liquidator benefits from liquidation
// May indicate self-liquidation setup
if (liquidator == borrower || linkedAddresses[liquidator][borrower]) {
    // Potential self-liquidation
}
```

---

## 5. Arbitrage-Related MEV

### 5.1 DEX Arbitrage
**Description:** Exploiting price differences across DEXs

**Common Patterns:**
1. **Simple Arbitrage:** A→B on DEX1, B→A on DEX2
2. **Triangular Arbitrage:** A→B→C→A across multiple pools
3. **Statistical Arbitrage:** Exploiting temporary mispricings

**Impact on Protocols:**
```solidity
// Protocols using DEX spot prices are vulnerable
// Arbitrageurs correct prices, but extracting value

// If your protocol relies on:
uint256 price = dex.getSpotPrice();  // ❌ Subject to arbitrage
// The price you see may be pre/post arbitrage correction
```

### 5.2 Backrunning for Arbitrage
**Description:** Executing arbitrage immediately after price-moving transactions

**Attack Flow:**
```
Block N:
  TX 1: Large swap moves price on DEX A
  TX 2: Arbitrageur trades DEX A → DEX B (backrun)
```

**Detection in Code:**
```solidity
// Look for callbacks/hooks that could be exploited for backrunning
function swap(...) external {
    // ... swap logic ...
    
    // ❌ External call after state change - backrun opportunity
    ISwapCallback(msg.sender).swapCallback(amount0, amount1, data);
}
```

---

## 6. Protocol-Level MEV Defenses

### 6.1 Private Mempool Integration
**Description:** Route transactions through private channels

**Implementation:**
```solidity
// Frontend integration with Flashbots Protect RPC
// https://rpc.flashbots.net

// Transaction flow:
// User → Flashbots RPC → Block Builder → On-chain
// Bypasses public mempool entirely
```

**Trade-offs:**
- ✅ Protects against sandwich attacks
- ✅ Failed TXs don't cost gas
- ❌ Centralization concerns
- ❌ May have slower inclusion

### 6.2 Commit-Reveal Schemes
**Description:** Hide transaction details until execution

**Implementation:**
```solidity
mapping(bytes32 => CommitData) public commits;

struct CommitData {
    address user;
    uint256 commitBlock;
    bool revealed;
}

function commit(bytes32 hash) external {
    commits[hash] = CommitData({
        user: msg.sender,
        commitBlock: block.number,
        revealed: false
    });
}

function reveal(
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    uint256 minAmountOut,
    uint256 salt
) external {
    bytes32 hash = keccak256(abi.encodePacked(
        tokenIn, tokenOut, amountIn, minAmountOut, salt
    ));
    
    CommitData storage c = commits[hash];
    require(c.user == msg.sender, "Not committer");
    require(block.number >= c.commitBlock + REVEAL_DELAY, "Too early");
    require(block.number <= c.commitBlock + REVEAL_WINDOW, "Too late");
    require(!c.revealed, "Already revealed");
    
    c.revealed = true;
    _executeSwap(tokenIn, tokenOut, amountIn, minAmountOut);
}
```

### 6.3 Batch Auctions
**Description:** Aggregate orders and execute at uniform clearing price

**Example (CoW Protocol style):**
```solidity
// Off-chain order aggregation
// Solver computes optimal batch settlement
// Single on-chain TX with uniform price
// No ordering = no sandwich opportunity
```

### 6.4 Dutch Auctions for Liquidations
**Description:** Gradually increasing liquidation incentive

**Implementation:**
```solidity
function getLiquidationBonus(address user) public view returns (uint256) {
    uint256 timeUnderwater = block.timestamp - underwaterSince[user];
    
    // Start at 2%, increase to 15% over 1 hour
    uint256 bonus = MIN_BONUS + (timeUnderwater * BONUS_RATE);
    return bonus > MAX_BONUS ? MAX_BONUS : bonus;
}
```

**Benefits:**
- Reduces MEV competition spike at threshold
- More efficient price discovery
- Discourages block-stuffing attacks

### 6.5 Time-Weighted Order Execution
**Description:** Spread large orders over time/blocks

**Implementation:**
```solidity
struct TWAPOrder {
    uint256 totalAmount;
    uint256 executedAmount;
    uint256 startBlock;
    uint256 endBlock;
    uint256 minPrice;
}

function executeChunk(uint256 orderId) external {
    TWAPOrder storage order = orders[orderId];
    uint256 elapsed = block.number - order.startBlock;
    uint256 duration = order.endBlock - order.startBlock;
    
    uint256 targetExecuted = order.totalAmount * elapsed / duration;
    uint256 toExecute = targetExecuted - order.executedAmount;
    
    _executeSwap(toExecute, order.minPrice);
    order.executedAmount += toExecute;
}
```

---

## 7. MEV Detection Checklist for Auditors

### 7.1 Swap Functions
- [ ] Is `amountOutMin` / `amountInMax` enforced?
- [ ] Is deadline parameter used and validated?
- [ ] Are slippage parameters user-controlled (not hardcoded)?
- [ ] Is slippage tolerance reasonable (< 3% for majors)?
- [ ] Are multi-hop swaps protected at each hop?

### 7.2 Oracle Usage
- [ ] Is spot price used directly? (vulnerable)
- [ ] Is TWAP window sufficient (> 30 min for high value)?
- [ ] Is oracle liquidity checked?
- [ ] Are multiple oracle sources used with deviation checks?
- [ ] Is oracle update delay considered?

### 7.3 Liquidations
- [ ] Can liquidations be front-run?
- [ ] Is there MEV protection for liquidators?
- [ ] Are Dutch auctions used for efficient price discovery?
- [ ] Is self-liquidation considered?
- [ ] Can block-stuffing delay liquidation profitably?

### 7.4 Liquidity Provision
- [ ] Can liquidity be added/removed in same block? (JIT vulnerable)
- [ ] Is there minimum liquidity period?
- [ ] Are fees claimable immediately after mint?
- [ ] Is LP token price manipulation possible?

### 7.5 External Interactions
- [ ] Are there callbacks after state changes? (backrun opportunity)
- [ ] Can flash loans interact with the protocol?
- [ ] Is reentrancy protected with state changes first?

---

## 8. Real-World Case Studies

### 8.1 Mango Markets Exploit ($117M, 2022)
**Type:** Oracle Manipulation
**Mechanism:**
1. Attacker used two accounts with $10M each
2. Account A shorted MNGO perpetuals
3. Account B bought MNGO spot (inflated price 2000%)
4. Account B's collateral value jumped to $400M+
5. Borrowed against inflated collateral
6. Drained all available assets

**Lesson:** Centralized exchange price feeds + low liquidity = extreme manipulation risk

### 8.2 Euler Finance Exploit ($197M, 2023)
**Type:** Flash Loan + Liquidation Logic
**Mechanism:**
1. Flash loan to create underwater position
2. Exploit liquidation logic to receive more than owed
3. Bad debt created, protocol drained

**Lesson:** Liquidation paths must account for flash loan scenarios

### 8.3 Sandwich Bot "jaredfromsubway.eth" 
**Statistics (2023-2025):**
- Controlled ~70% of Ethereum sandwich attacks
- Extracted $40M+ in 2025 alone
- Average profit: $3-5 per sandwich (volume game)

**Lesson:** MEV is dominated by sophisticated, persistent operators

### 8.4 Makina Finance Exploit ($4.13M, January 2026)
**Type:** Protocol Exploit + MEV Builder Front-Running
**Date:** January 20, 2026

**Unique Aspect: Attacker Got Sandwiched**

**Attack Flow:**
1. Attacker identified vulnerability in Makina Finance
2. Prepared exploit transaction involving large swap
3. Exploit moved 4.24M USDC → 1,299 ETH via Uniswap V3
4. Transaction routed through Curve (DAI, 3Crv pools) and Aave
5. **Plot twist:** MEV builder detected exploit in mempool
6. Builder front-ran the attacker with identical exploit (higher gas)
7. Original attacker lost their exploit bounty to MEV infrastructure

**On-chain Details:**
- Block: 24,273,362 (Ethereum mainnet)
- Gas fee: ~$0.50 (carefully crafted)
- Final funds split: $3.3M + $880K in two wallets

**Technical Mechanism:**
```
Mempool Observation:
  ┌─────────────────────────────────────────┐
  │ Attacker's Pending Exploit TX           │
  │ - Exploit Makina → Get 4.24M USDC       │
  │ - Swap on Uniswap V3 → 1,299 ETH        │
  └─────────────────────────────────────────┘
                    ↓
  MEV Builder Detection
                    ↓
  ┌─────────────────────────────────────────┐
  │ Builder's Cloned TX (Higher Gas)        │
  │ - Replicated exploit logic              │
  │ - Guaranteed block inclusion priority   │
  │ - Captured the entire bounty            │
  └─────────────────────────────────────────┘
```

**Lessons:**
1. **MEV infrastructure is predatory even to attackers** - Exploiters must use private mempools
2. **Multi-protocol paths increase detection surface** - Routing through Curve/Aave/Uniswap created observable patterns
3. **Block builders have unique MEV advantages** - They control ordering AND can replicate transactions
4. **"MEV on MEV" is real** - Sophisticated operators hunt other MEV extractors

**Audit Implications:**
- Even "attackers" need MEV protection when exploiting
- Protocols should consider this when designing bug bounty programs
- Private transaction submission is now table stakes for all high-value operations

### 8.5 JIT Liquidity on Uniswap V3
**Statistics:**
- First documented: November 2021
- Peak activity: 2022-2023
- Affects ~10% of large swaps
- LP dilution: 15-40% on targeted swaps

---

## 9. Audit Code Patterns

### 9.1 Vulnerable Swap (No Protection)
```solidity
// ❌ CRITICAL: No slippage, no deadline
function swapExact(uint256 amountIn) external {
    router.swapExactTokensForTokens(
        amountIn,
        0,                      // No minimum
        path,
        msg.sender,
        type(uint256).max       // No deadline
    );
}
```

### 9.2 Vulnerable Oracle (Spot Price)
```solidity
// ❌ HIGH: Direct spot price usage
function getCollateralValue(uint256 amount) external view returns (uint256) {
    (uint256 r0, uint256 r1,) = pair.getReserves();
    uint256 price = r1 * 1e18 / r0;  // Spot price
    return amount * price / 1e18;
}
```

### 9.3 Vulnerable Liquidity (JIT Possible)
```solidity
// ❌ MEDIUM: No lockup, instant fee claim
function addLiquidity(uint256 amount) external returns (uint256 shares) {
    shares = _mint(amount);
    // Fees claimable immediately
}

function removeLiquidity(uint256 shares) external {
    _burn(shares);
    _claimFees();  // Same transaction
}
```

### 9.4 Vulnerable Liquidation (Front-runnable)
```solidity
// ❌ HIGH: Instant liquidation on price change
function liquidate(address user) external {
    uint256 price = oracle.latestAnswer();  // Latest, not committed
    require(healthFactor(user, price) < 1e18);
    // Front-runner sees oracle update TX, front-runs this
}
```

---

## 10. Severity Classification

### 10.1 L1 (Ethereum Mainnet) Severity

| MEV Vector | Typical Severity | User Impact | Protocol Impact |
|------------|-----------------|-------------|-----------------|
| Sandwich (no slippage) | CRITICAL | Direct fund loss | Reputation damage |
| Sandwich (high slippage) | HIGH | Partial fund loss | User churn |
| JIT Liquidity | MEDIUM | LP dilution | LP exodus |
| Oracle Manipulation | CRITICAL | Fund loss, bad debt | Protocol insolvency |
| Liquidation Front-run | MEDIUM | Faster liquidation | Increased MEV |
| Arbitrage Backrun | LOW | Indirect (worse prices) | Value extraction |

### 10.2 L2 (Rollups with Private Mempools) Severity

Based on arXiv:2601.19570 research findings:

| MEV Vector | L1 Severity | L2 Severity | Rationale |
|------------|-------------|-------------|-----------|
| Sandwich Attack | CRITICAL | LOW-MEDIUM | Probabilistic, often unprofitable |
| JIT Liquidity | MEDIUM | LOW | Requires mempool visibility |
| Oracle Manipulation | CRITICAL | HIGH | Still possible via sequencer |
| Liquidation Front-run | MEDIUM | LOW-MEDIUM | Sequencer controls ordering |
| Backrunning | LOW | INFORMATIONAL | Limited visibility |

**L2 MEV Considerations:**
- Private mempools eliminate ~90% of traditional sandwich risk
- Sequencer becomes single point for MEV extraction
- Centralized sequencers may engage in MEV themselves
- Decentralized sequencer solutions (shared sequencing) change the dynamics
- Block builders for L2 batch submission have new MEV opportunities

### 10.3 Alternative L1s (Solana, etc.)

| Chain | MEV Landscape | Notable Issues |
|-------|---------------|----------------|
| Solana | High ($500M+ in 18 months) | Leader schedule known in advance |
| BSC | Medium | Centralized validators |
| Avalanche | Medium-Low | Subnet architecture varies |
| Polygon PoS | Medium | Similar to L1 Ethereum |

---

## References

1. Flashbots - MEV Explore: https://explore.flashbots.net/
2. EigenPhi - MEV Analytics: https://eigenphi.io/
3. "Flash Boys 2.0" - Daian et al. (2020)
4. "Quantifying MEV" - Flashbots (2021)
5. "TWAP Oracle Attacks" - Mackinga et al. (2022)
6. Uniswap V3 Whitepaper - JIT Liquidity Discussion
7. Trail of Bits - Uniswap V3 Audit (2021)
8. Chainlink - DeFi Security Best Practices
9. **[NEW]** "How to Serve Your Sandwich? MEV Attacks in Private L2 Mempools" - arXiv:2601.19570 (Jan 2026)
10. **[NEW]** PeckShield - Makina Finance Exploit Analysis (Jan 2026)

---

*This document is part of the Smart Contract Auditor vulnerability knowledge base.*
*Updated: 2026-02-06 02:00 AM*
