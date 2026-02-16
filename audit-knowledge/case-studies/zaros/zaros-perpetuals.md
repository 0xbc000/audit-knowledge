# Zaros Perpetuals - Case Study

## Protocol Overview

**Type:** Perpetual DEX + Market Making Engine
**Chain:** Multi-chain (L2 focused)
**TVL at Audit:** N/A (pre-launch)
**Audit Date:** January 2025

## Architecture

```
PerpsEngine (Tree Proxy Pattern)
├── OrderBranch
├── SettlementBranch  
├── LiquidationBranch
├── TradingAccountBranch
└── PerpMarketBranch

MarketMakingEngine (Tree Proxy Pattern)
├── CreditDelegationBranch
├── FeeDistributionBranch
├── VaultRouterBranch
└── StabilityBranch

ZlpVault (ERC4626 UUPS Proxy)
└── Stores LP assets separately
```

## Key Mechanisms

### Credit Delegation System
- Vaults delegate credit to markets
- Each vault can connect to multiple markets
- Credit is distributed based on weight ratios

### Fee Distribution
- Trading fees → WETH conversion → distribute to vaults and protocol
- Uses per-share accounting for fair distribution

---

## Vulnerabilities Found

### [C-01] Weight Distribution Bug - All Markets Share Same Weight

**File:** `src/market-making/leaves/Vault.sol`
**Lines:** 508-533

#### Vulnerable Code

```solidity
function updateVaultAndCreditDelegationWeight(
    Data storage self,
    uint128[] memory connectedMarketsIdsCache
) internal {
    // Get total assets as new weight
    uint128 newWeight = uint128(IERC4626(self.indexToken).totalAssets());

    for (uint256 i; i < connectedMarketsIdsCache.length; i++) {
        CreditDelegation.Data storage creditDelegation =
            CreditDelegation.load(self.id, connectedMarkets.at(i).toUint128());

        // BUG: Every market gets the SAME weight value
        creditDelegation.weight = newWeight;
    }

    // BUG: totalWeight = newWeight, not (newWeight * numMarkets)
    self.totalCreditDelegationWeight = newWeight;
}
```

#### Root Cause

The function sets every market's `weight` to the same value (`newWeight`), and sets `totalCreditDelegationWeight` to `newWeight` as well.

When calculating each market's share later:
```solidity
creditDelegationShareX18 = ud60x18(creditDelegation.weight).div(ud60x18(totalCreditDelegationWeightCache));
// = newWeight / newWeight = 1 (100%)
```

Every market thinks it has 100% of the credit delegation!

#### Impact

- **Severity:** Critical
- **Type:** Accounting Error
- With N connected markets, total allocated credit = N × 100% = N00%
- Leads to over-allocation of credit
- Can cause protocol insolvency

#### Correct Implementation

```solidity
function updateVaultAndCreditDelegationWeight(
    Data storage self,
    uint128[] memory connectedMarketsIdsCache
) internal {
    uint128 newWeight = uint128(IERC4626(self.indexToken).totalAssets());
    uint256 numMarkets = connectedMarketsIdsCache.length;
    
    // Option A: Each market gets equal share
    uint128 weightPerMarket = newWeight / uint128(numMarkets);
    
    for (uint256 i; i < numMarkets; i++) {
        CreditDelegation.Data storage creditDelegation =
            CreditDelegation.load(self.id, connectedMarkets.at(i).toUint128());
        creditDelegation.weight = weightPerMarket;
    }
    
    // Total = sum of all weights
    self.totalCreditDelegationWeight = weightPerMarket * uint128(numMarkets);
    
    // Option B: Or use custom weights per market (more flexible)
}
```

---

## Patterns to Watch

### In Similar Protocols

1. **Weight/Share Distribution**
   - Always verify: sum(individual_weights) == total_weight
   - Check loop logic carefully

2. **Credit Delegation Systems**
   - Multi-market allocation must sum to 100%
   - Watch for per-share vs per-total confusion

3. **Tree Proxy Pattern**
   - Storage slot collisions between branches
   - Upgrade path security

---

## Detection Heuristics

```
IF protocol has:
  - Multiple recipients sharing a pool
  - Weight-based distribution
  - Loop setting weights
THEN check:
  - Is totalWeight = sum(weights)?
  - Does each iteration set unique weight or same value?
  - Are percentages summing to 100%?
```

## Tags

`perpetuals` `market-making` `erc4626` `weight-distribution` `accounting` `critical`
