# Lending Protocol Vulnerability Patterns

Source: AAVE v3.3 Sherlock Audit Analysis (2025-01)
Last Updated: 2026-02-03

These patterns represent vulnerabilities that **automated tools typically cannot detect** because they require:
- Business logic understanding
- Cross-function state flow analysis
- Economic attack vector reasoning
- Protocol-specific invariant knowledge

---

## 1. Silent Permit Validation Bypass

**Pattern:** Try-catch blocks that silently ignore permit failures

**Example:**
```solidity
try IERC20WithPermit(asset).permit(...) {} catch {}  // <-- DANGER
// Operation continues even if permit fails!
SupplyLogic.executeSupply(...);
```

**Why Tools Miss It:** 
- No direct vulnerability pattern (no reentrancy, overflow)
- Requires understanding that permit failure should halt execution

**Detection Questions:**
- Does the function use permit with try-catch?
- Does it continue execution after catch?
- Is there an existing approval that could be used instead?

**Impact:** Unauthorized token operations, signature replay attacks

---

## 2. State Update Order in Bad Debt Handling

**Pattern:** Interest rates updated incorrectly when burning bad debt without actual token transfers

**Example:**
```solidity
function _burnBadDebt(...) {
  _burnDebtTokens(...);  // Updates interest rates
  // BUT: No actual token transfer happens for bad debt!
}

function _burnDebtTokens(...) {
  debtReserve.updateInterestRatesAndVirtualBalance(
    debtReserveCache,
    debtAsset,
    actualDebtToLiquidate,  // <-- Treated as liquidity added, but it wasn't
    0
  );
}
```

**Why Tools Miss It:**
- Requires understanding of interest rate model assumptions
- No obvious code flaw, just wrong accounting logic

**Detection Questions:**
- When burning bad debt, are interest rates updated?
- Does the update assume liquidity was added?
- Is there actually a token transfer?

**Impact:** Protocol-wide interest rate distortion

---

## 3. Configuration State Inconsistency

**Pattern:** Allowing contradictory configuration values

**Example:**
```solidity
function setBorrowableInIsolation(bool borrowable) {
  // Missing: require(!borrowable || getDebtCeiling(self) > 0)
  self.data = ...;  // Allows borrowable=true with debtCeiling=0
}
```

**Why Tools Miss It:**
- Each setter looks valid in isolation
- Requires understanding the semantic relationship between parameters

**Detection Questions:**
- What parameters are logically dependent on each other?
- Can setter functions create invalid state combinations?
- Are there cross-parameter invariants that should be enforced?

**Impact:** User transactions fail unexpectedly, gas loss, poor UX

---

## 4. DoS Through Unbounded Iteration

**Pattern:** Loop iterates through all reserves regardless of relevance

**Example:**
```solidity
function _burnBadDebt(...) {
  for (uint256 i; i < reservesCount; i++) {  // Could be 100+ reserves
    if (!userConfig.isBorrowing(i)) continue;  // Still costs gas
    // Process reserve
  }
}
```

**Why Tools Miss It:**
- Loop bounds are "valid" (reservesCount is known)
- DoS happens only under specific gas/congestion conditions

**Detection Questions:**
- Does the function iterate over all reserves/users/positions?
- What's the gas cost per iteration?
- Could this exceed block gas limit on congested L1s?

**Impact:** Liquidation failures, cascading insolvency

---

## 5. Dust Manipulation to Prevent Bad Debt Accounting

**Pattern:** Small collateral additions block bad debt cleanup

**Example:**
```solidity
// Deficit accounting only occurs when hasNoCollateralLeft == true
if (hasNoCollateralLeft && userConfig.isBorrowingAny()) {
  _burnBadDebt(...);
}

// Attack: Supply 1 wei of different collateral before liquidation
// Result: hasNoCollateralLeft = false, bad debt never accounted
```

**Why Tools Miss It:**
- Requires understanding multi-step attack scenarios
- Each individual step is valid

**Detection Questions:**
- What conditions trigger bad debt accounting?
- Can an attacker manipulate those conditions cheaply?
- Is there economic incentive to do so?

**Impact:** Permanent bad debt accumulation, protocol insolvency

---

## 6. Cross-Chain WETH Implementation Differences

**Pattern:** WETH behavior varies across chains

**Example:**
```solidity
// Works on Ethereum, Optimism (standard WETH9):
aWETH.transferFrom(msg.sender, address(this), amount);
// Handles src == msg.sender case

// Fails on Arbitrum (custom WETH):
// No special handling for src == msg.sender
// Reverts without explicit approval
```

**Why Tools Miss It:**
- Static analysis uses single implementation
- Requires knowledge of chain-specific token implementations

**Detection Questions:**
- Which chains is this deployed on?
- Are there ERC20/WETH variations on those chains?
- Does the code assume standard behavior?

**Impact:** Complete function breakage on specific chains

---

## 7. Residual Debt After "Full" Repayment

**Pattern:** Interest accrual between balance read and burn creates residual debt

**Example:**
```solidity
// User wants to repay everything
if (params.amount == type(uint256).max) {
  params.amount = aToken.balanceOf(msg.sender);  // Read balance
}
// Interest accrues here...
uint256 paybackAmount = min(variableDebt, params.amount);
// ...debt grew, payback doesn't cover it all

// Check passes: variableDebt - paybackAmount != 0
// User thinks they repaid, but residual remains
```

**Why Tools Miss It:**
- Race condition between balance read and burn
- Requires understanding of interest accrual timing

**Detection Questions:**
- Is there a time gap between balance check and state change?
- Can interest accrue during this gap?
- What happens to the small residual?

**Impact:** Undercollateralized positions, unexpected liquidations

---

## 8. Library Function Access Control

**Pattern:** Library functions lack access control (by design), but callers don't add it

**Example:**
```solidity
// Library function - no access control by design
library LiquidationLogic {
  function executeLiquidationCall(...) external {
    // Anyone can call with any parameters
  }
}

// If Pool.sol exposes this without additional checks...
```

**Why Tools Miss It:**
- Libraries intentionally have no access control
- Issue is in the call site, not the library

**Detection Questions:**
- Does the Pool/main contract add access control when calling library?
- Can external users directly call with arbitrary parameters?
- Should certain actions require special roles?

**Impact:** Unauthorized liquidations, fund theft

---

## General Detection Strategy

### For any lending/borrowing protocol, ask:

1. **Accounting Invariants**
   - Do supply/borrow/repay operations maintain balance invariants?
   - Are interest rate updates consistent with actual liquidity changes?

2. **State Machine Transitions**
   - Can users get into states they shouldn't be in?
   - Are all state transitions properly validated?

3. **Economic Attack Vectors**
   - What's the cost to grief/attack vs potential gain?
   - Can flash loans amplify any attack?

4. **Cross-Function Dependencies**
   - Do functions assume state from other functions?
   - Can an attacker manipulate intermediate state?

5. **Gas/Execution Limits**
   - Are there unbounded loops?
   - What happens under high gas prices?

---

## Prompt Enhancement for AI Auditors

When auditing lending protocols, specifically check for:

```
1. Permit operations with try-catch that continue on failure
2. Bad debt burning that updates interest rates without actual transfers
3. Configuration setters that can create logically impossible states
4. Loops over all reserves/users that could hit gas limits
5. Dust deposits that could prevent important state transitions
6. Chain-specific token implementations (especially WETH)
7. Interest accrual between balance reads and state updates
8. Library functions exposed without access control in caller
```
