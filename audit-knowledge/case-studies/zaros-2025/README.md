# Zaros Part 2 - 案例研究

## 基本資訊

| 項目 | 內容 |
|------|------|
| 平台 | CodeHawks |
| 時間 | 2025-01-20 ~ 2025-02-06 |
| 獎金 | $70,000 USDC |
| 程式碼行數 | ~3,258 nSLOC |
| 協議類型 | Perpetuals DEX |
| 鏈 | Arbitrum, Monad |

## 協議概述

Zaros 是永續合約 DEX，由兩個核心引擎組成：

1. **PerpsEngine**: 處理永續合約交易
2. **MarketMakingEngine**: 管理 LP vault 和信用委託

### 核心機制
- ZLP Vaults: LP 存入 collateral，提供流動性
- Credit Delegation: Vault 將信用額度委託給各個 market
- Debt Distribution: Market 的債務按比例分配給 vaults
- USDz: 內部穩定幣，用於結算 trader 盈利

## 發現的漏洞

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 (weight) | high | code-confirmed | ✅ |
| H-02 (comparison) | high | code-confirmed | ✅ |
| H-03 (oracle) | medium | logic-inference | ❌ |
| H-04 (array) | high | code-confirmed | ✅ |
| H-05 (distribution) | medium | logic-inference | ❌ |
| M-06 (selector) | low | logic-inference | ❌ |
| M-07 (rebalance) | medium | logic-inference | ❌ |

---

### High Severity

#### 1. 權重分配錯誤
- **檔案**: `Vault.sol` → `updateVaultAndCreditDelegationWeight` (Line 508-536)
- **問題**: 每個 market 都被分配全部權重（100%），而非按比例
- **程式碼**:
```solidity
for (uint256 i; i < connectedMarketsIdsCache.length; i++) {
    creditDelegation.weight = newWeight;  // ❌ 每個都拿到 100%
}
self.totalCreditDelegationWeight = newWeight;
```
- **影響**: 2 個 market = 200% 總分配，Over-leveraging, insolvency
- **Pattern**: [weight-distribution-error.md](../../vulnerability-patterns/business-logic/weight-distribution-error.md)

#### 2. 比較運算符反轉（結算邏輯相反）
- **檔案**: `CreditDelegationBranch.sol` → `settleVaultDebts` (Line 436)
- **問題**: 用 `.lt(SD59x18_ZERO)` 判斷是否需要賣資產，但邏輯反了
- **程式碼**:
```solidity
// 邏輯應該是：
// debt > 0 (正債務) → 賣資產換 USDC
// debt < 0 (負債務/有餘額) → 賣 USDC 換資產

// ❌ 錯誤實現
if (ctx.vaultUnsettledRealizedDebtUsdX18.lt(SD59x18_ZERO)) {
    // 這裡執行「賣資產換 USDC」
    // 但 .lt(ZERO) 表示 debt < 0，應該是反過來！
}
```
- **影響**: 結算功能完全反向，債務不減反增
- **Pattern**: [comparison-operator-inversion.md](../../vulnerability-patterns/business-logic/comparison-operator-inversion.md)

#### 3. Oracle 價格過期風險
- **檔案**: `StabilityBranch.sol` → `fulfillSwap`
- **問題**: 使用簽名價格數據執行 swap，但未驗證時間戳新鮮度
- **攻擊場景**:
  1. 用戶發起 swap 請求
  2. 價格大幅變動
  3. Keeper 使用舊價格數據執行
  4. 用戶獲得不公平的匯率
- **影響**: 價格操縱，套利攻擊

#### 4. FeeConversionKeeper 陣列處理錯誤
- **檔案**: `FeeConversionKeeper.sol` → `checkUpkeep` / `performUpkeep`
- **問題**: `checkUpkeep` 返回的陣列長度過大，包含空值 (address(0), uint256(0))
- **程式碼**:
```solidity
// checkUpkeep 分配過大的陣列
uint128[] memory marketIds = new uint128[](liveMarketIds.length * 10);
address[] memory assets = new address[](liveMarketIds.length * 10);
// 只填充部分，其餘是 0 值

// performUpkeep 遍歷時遇到 address(0)
// → revert Errors.CollateralDisabled(address(0))
```
- **影響**: Keeper 無法正常執行，費用轉換功能癱瘓

#### 5. Distribution 值累積錯誤
- **檔案**: `Distribution.sol` → `_updateLastValuePerShare`
- **問題**: Actor 的 shares 更新時，可能沒有正確累積之前的 value change
- **風險點**:
  - `setActorShares` 更新 shares 前未先累積
  - `accumulateActor` 可能不被調用
- **影響**: 用戶獎勵/收益計算錯誤

### Medium Severity

#### 6. Function Selector Collision
- **檔案**: `RootProxy.sol`
- **問題**: 多個函數可能有相同的 selector，導致調用錯誤的實現
- **影響**: 協議邏輯可能被破壞

#### 7. rebalanceVaultAssets 餘額不足
- **檔案**: `VaultRouterBranch.sol`
- **問題**: 重新平衡時可能因 ERC20 餘額不足而 revert
- **影響**: 資產重平衡功能無法正常工作

### Low Severity

#### 8. ERC7201 不合規
- **檔案**: 多個 Library
- **問題**: Storage slot 計算沒有 `& ~bytes32(uint256(0xff))` 確保最後一個 byte 是 0x00
- **程式碼**:
```solidity
// 當前實現
bytes32 internal constant LOCATION = keccak256(abi.encode(uint256(keccak256("...")) - 1));
// 結果: 0x...c840

// ERC7201 標準
bytes32 internal constant LOCATION = keccak256(abi.encode(uint256(keccak256("...")) - 1)) & ~bytes32(uint256(0xff));
// 結果: 0x...c800
```
- **影響**: 未來升級可能有 storage collision

#### 9. 使用過時的 Curve 合約
- **問題**: 調用了已 deprecated 的 CurveRegistryExchange 函數
- **影響**: 未來 Curve 更新可能導致功能失效

## 學到的 Patterns

### 1. 審計 Perp DEX 時的關鍵問題

```
✅ Credit delegation 權重分配是否正確？
✅ 債務結算方向是否正確？
✅ 清算條件是否正確？
✅ Oracle 價格是否有有效性檢查？
```

### 2. 業務邏輯 Bug 的共同特徵

- 不是語法錯誤，編譯器抓不到
- 不是常見漏洞（reentrancy），靜態分析抓不到
- 需要理解業務邏輯才能發現
- 用數字舉例可以快速驗證

### 3. 有效的審計方法

1. 先列出 invariants
2. 找可能違反 invariant 的函數
3. 用 prompt template 針對性分析
4. 用數字驗證邏輯

## 關鍵 Invariants

```solidity
// 1. Credit 總和 <= Vault 資產
assert(sum(market.delegatedCredit) <= vault.totalAssets)

// 2. 權重分配正確
assert(sum(creditDelegation.weight) == vault.totalWeight)

// 3. 結算後債務減少
assert(debtAfterSettle <= debtBeforeSettle)
```

## 原始碼位置

本地 clone: `/Users/billyc/clawd/zaros-audit/`

## 參考連結

- [CodeHawks 結果頁面](https://codehawks.cyfrin.io/c/2025-01-zaros-part-2/results)
- [GitHub Repo](https://github.com/Cyfrin/2025-01-zaros-part-2)
- [Zaros 文檔](https://docs.zaros.fi/)
