# Yield Tokenization Attack Patterns

Source: Napier Finance Sherlock Audit 2024-01 (8 High, 22 Medium findings)
Last Updated: 2026-02-03

These patterns focus on **yield tokenization protocols** that split assets into Principal Tokens (PT) and Yield Tokens (YT).

---

## Protocol Overview

Yield tokenization protocols (Pendle, Napier, Sense, Spectra) allow users to:
- Deposit yield-bearing assets
- Receive PT (principal) + YT (yield rights)
- Trade PT/YT separately
- Redeem at maturity

Key components:
- **Tranche:** Splits deposits into PT + YT
- **Adaptor/Adapter:** Interfaces with underlying yield source
- **AMM Pool:** Trades PT against underlying
- **Scale/Exchange Rate:** PT value relative to underlying

---

## 1. Scale/Exchange Rate Manipulation

### 1.1 Max Scale Inflation Attack (HIGH)
**Pattern:** Attacker inflates max scale at initialization to lock unfavorable conditions

```solidity
// Max scale is recorded and never decreases
if (currentScale > maxScale) {
    maxScale = currentScale;  // Lock highest ever seen
}

// Later: conditions depend on maxScale
if (currentScale / maxScale >= threshold) {
    // "Sunny day" - YT holders get bonus
}
```

**Attack Flow:**
1. At protocol launch, deposit minimal amount
2. Donate large amount to adapter directly
3. Scale becomes artificially high (e.g., 1000x normal)
4. Max scale is locked at this inflated value
5. Withdraw donated amount
6. Scale returns to normal, but maxScale stays high
7. `currentScale / maxScale` is always tiny → permanent "cloudy day"

**Impact:** YT holders never receive sunny day benefits

**Detection Questions:**
- Is there a max scale or similar high-water mark?
- Can it be manipulated at initialization?
- What conditions depend on max vs current scale?

---

### 1.2 Scale Decrease Race Condition (HIGH)
**Pattern:** When scale decreases, early redeemers get more assets

```solidity
// Interest accrued per share changes with scale
uint256 yield = (userShares / lscale) - (userShares / currentScale);

// If scale drops, earlier calculation is more favorable
```

**Attack Flow:**
1. Monitor for scale decrease events (slashing, loss)
2. Race to redeem before others
3. Get more underlying per share
4. Later redeemers receive less

**Impact:** First-mover advantage, unfair yield distribution

**Detection Questions:**
- What happens when scale decreases?
- Is yield calculated at time of claim or accrual?
- Can users front-run scale updates?

---

## 2. PT/YT Holder Adversarial Dynamics

### 2.1 Zero-Amount Yield Theft (HIGH)
**Pattern:** Calling redemption with zero amount bypasses checks but executes side effects

```solidity
function redeemWithYT(address from, address to, uint256 amount) {
    // Burns are skipped when amount = 0
    _burnFrom(from, amount);  // Burns 0, no revert
    yt.burnFrom(from, msg.sender, amount);  // Burns 0, no revert
    
    // But yield is still transferred!
    uint256 yield = accruedYield[from];  // Non-zero
    underlying.transfer(to, yield);
    accruedYield[from] = 0;
}
```

**Attack Flow:**
1. Identify account with accrued yield
2. Call `redeemWithYT(victim, attacker, 0)`
3. No tokens burned (checks pass)
4. Yield transferred to attacker

**Impact:** Direct theft of accrued yield

**Detection Questions:**
- What happens when amount = 0?
- Are there side effects independent of main action?
- Is caller authorization checked for ALL effects?

---

### 2.2 Tilt Mechanism Gaming (MEDIUM)
**Pattern:** PT holders avoid losses by manipulating conditions

```solidity
// On "sunny day": PT holders lose θ% to YT holders
// On "cloudy day": PT holders keep everything

// Condition: sunny if scale/maxScale >= (1 - θ)
```

**Attack Flow:**
1. PT holder artificially inflates maxScale (see 1.1)
2. Ensure condition always evaluates to "cloudy day"
3. PT holders never pay tilt to YT holders

**Impact:** YT holders lose expected principal bonus

---

## 3. Adapter/Adaptor Vulnerabilities

### 3.1 Buffer Manipulation DoS (HIGH)
**Pattern:** Exact deposit calculation drains buffer to zero

```solidity
// Redemption requires buffer > assets
if (assets > bufferEth) revert InsufficientBuffer();

// Buffer percentage target
uint256 targetBuffer = totalAssets * targetPct / 100;
```

**Attack Flow:**
1. Calculate exact deposit amount using formula:
   `(CurrentTotalAssets + Deposit) * targetPct - Deposit = 0`
2. Deposit that amount
3. Buffer becomes exactly 0
4. All redemptions revert
5. Repeat as needed to maintain DoS

**Impact:** Complete redemption freeze

**Detection Questions:**
- Is there a buffer for instant redemptions?
- Can the buffer be drained to exactly zero?
- What happens during buffer refill period?

---

### 3.2 Accounting Mismatch Between Adapters (HIGH)
**Pattern:** Similar adapters handle conversion differently

```solidity
// Adapter A (WRONG)
function totalAssets() returns (uint256) {
    return withdrawalQueue + buffer + stETH.balanceOf(this);
    // stETH balance not converted to ETH!
}

// Adapter B (CORRECT)  
function totalAssets() returns (uint256) {
    uint256 stakedBalance = sfrxETH.balanceOf(this);
    uint256 inFrxEth = sfrxETH.convertToAssets(stakedBalance);
    return withdrawalQueue + buffer + inFrxEth;
}
```

**Impact:** Incorrect share calculations, potential fund loss

**Detection Questions:**
- Are similar adapters implemented consistently?
- Is underlying vs derivative accounting correct?
- Does `totalAssets()` mix units?

---

### 3.3 Prefunded Operation Race (MEDIUM)
**Pattern:** Prefunded deposits can be stolen via race

```solidity
// Anyone can call after funds are sent
function prefundedDeposit() external {
    uint256 assets = token.balanceOf(this) - lastKnown;
    // Mints shares to... address(this)? msg.sender?
    _mint(address(this), shares);  // Recoverable
    // vs
    _mint(msg.sender, shares);  // Thief gets them!
}
```

**Impact:** MEV bots can steal pending deposits

---

## 4. AMM Pool Vulnerabilities

### 4.1 LP Token Valuation Assumption (HIGH)
**Pattern:** Assuming fixed ratio between LP tokens and underlying

```solidity
// WRONG: Assumes 1 LP = 3 PT forever
exactBaseLptIn * N_COINS  // N_COINS = 3

// REALITY: LP token value changes based on:
// - Pool imbalance
// - Fee accumulation  
// - Underlying PT values
```

**Attack Flow:**
1. Imbalance the underlying Curve pool
2. LP token no longer equals 3 PT
3. Swap at favorable rate in Napier pool
4. Profit from valuation mismatch

**Impact:** Arbitrage losses for LPs

**Detection Questions:**
- How are LP tokens valued?
- Is the valuation dynamic or static?
- What assumptions does valuation make?

---

### 4.2 Exchange Rate Edge Cases (MEDIUM)
**Pattern:** AMM math fails at specific exchange rates

```solidity
// Division by zero when rate = 1
uint256 result = amount / (exchangeRate - 1);  // Reverts!
```

**Impact:** DoS of swap functionality

---

## 5. Maturity and Expiry Issues

### 5.1 Pre-Maturity vs Post-Maturity Logic (MEDIUM)
**Pattern:** Functions behave differently before/after maturity

```solidity
modifier checkExpiry {
    if (block.timestamp > maturity) {
        // Different logic path
    }
}

// Missing modifier on critical function
function sensitiveAction() external {  // No checkExpiry!
    // Can be called any time
}
```

**Detection Questions:**
- Which functions should only work pre-maturity?
- Which functions should only work post-maturity?
- Are all functions properly gated?

---

### 5.2 Interest Accrual During Redemption (MEDIUM)
**Pattern:** Interest accrues between balance read and burn

```solidity
uint256 balance = getBalance(user);  // Read
// ... time passes, interest accrues ...
burn(user, balance);  // Doesn't burn accrued interest

// User has residual balance after "full" redemption
```

**Impact:** Unexpected debt or residual balances

---

## 6. Yield Collection Timing

### 6.1 Frequent Collection Penalty (MEDIUM)
**Pattern:** More frequent claims result in less total yield

```solidity
// Yield calculated based on scale at claim time
// If scale fluctuates, timing matters

// User A: Claims daily
// User B: Claims once at maturity

// If scale ever decreases, User B captures more
```

**Impact:** Users punished for claiming yield

---

### 6.2 Yield Rounding Accumulation (LOW)
**Pattern:** Small rounding errors compound over many claims

```solidity
// Each claim rounds down
uint256 yield = userBalance * rate / PRECISION;  // Rounds down

// 100 small claims lose more to rounding than 1 large claim
```

---

## Detection Checklist for Yield Protocols

### Scale/Exchange Rate
- [ ] How is scale calculated?
- [ ] Is there a max scale or high-water mark?
- [ ] Can scale be manipulated at initialization?
- [ ] What happens when scale decreases?

### PT/YT Economics
- [ ] What conditions favor PT vs YT holders?
- [ ] Can conditions be manipulated?
- [ ] What happens with zero-amount operations?

### Adapter Safety
- [ ] Is buffer calculation safe from DoS?
- [ ] Are conversions (stETH→ETH) correct?
- [ ] Are prefunded operations race-safe?

### AMM Integration
- [ ] How are LP tokens valued?
- [ ] Are valuation assumptions always valid?
- [ ] Any edge cases in exchange rate math?

### Timing Issues
- [ ] Pre vs post maturity function access?
- [ ] Interest accrual timing attacks?
- [ ] Yield collection frequency effects?

---

## Prompt Enhancement for AI Auditors

When auditing yield tokenization protocols:

```
1. Max scale inflation attack (first depositor + donation)
2. Scale decrease race condition (who redeems first?)
3. Zero amount bypass for yield operations
4. Buffer manipulation DoS
5. Adapter conversion mismatches (stETH != ETH)
6. LP token valuation assumptions (not always N PT)
7. Sunny/cloudy day condition manipulation
8. Pre/post maturity function access control
9. Frequent claim penalty from rounding/timing
10. Interest accrual during redemption window
```

---

*Extracted from Napier Finance Sherlock Audit 2024-01*
