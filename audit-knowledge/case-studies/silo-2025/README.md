# Silo Finance - Code4rena March 2025

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Code4rena |
| **獎金池** | $50,000 USDC |
| **審計時間** | 2025-03-24 ~ 2025-03-31 |
| **協議類型** | ERC4626 Vault Aggregator / Lending |
| **原始碼** | [GitHub](https://github.com/code-423n4/2025-03-silo-finance) |
| **報告** | [C4 Report](https://code4rena.com/reports/2025-03-silo-finance) |

## 協議概述

Silo Finance 是一個非託管借貸協議，實現了無許可、隔離的借貸市場（稱為 silos）。
**SiloVault** 是 Morpho Vault 的 fork，作為管理流動性層，將流動性導入 Silo 的借貸市場或任何 ERC4626 vault。

### 核心架構
- **SiloVault.sol** - 主 vault 合約，符合 ERC4626 標準
- **PublicAllocator.sol** - 公開分配器
- **VaultIncentivesModule.sol** - 獎勵分配模組
- **DistributionManager.sol** - 獎勵分發管理

### 關鍵角色
- Owner - 完整控制權
- Curator - 管理市場 caps
- Allocator - 分配資金
- Guardian - 緊急操作

## 漏洞摘要

| ID | 嚴重度 | 標題 | 類型 |
|----|--------|------|------|
| M-01 | Medium | Supply 函數未檢查 market maxDeposit | ERC4626 整合 |
| M-02 | Medium | transfer 時 reward 計算錯誤（未同步 totalSupply） | 獎勵計算 |
| M-03 | Medium | 無法移除 revert on zero approval 的 token market | Token 相容性 |
| M-04 | Medium | deposit/withdraw 缺少 slippage 和 deadline 保護 | 用戶保護 |
| M-05 | Medium | feeShares mint 順序導致獎勵分配錯誤 | 獎勵計算 |
| M-06 | Medium | 獎勵分配精度問題 | 獎勵計算 |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| M-01 | high | code-confirmed | ✅ |
| M-02 | high | code-confirmed | ✅ |
| M-03 | medium | logic-inference | ❌ |
| M-04 | medium | logic-inference | ❌ |
| M-05 | high | code-confirmed | ✅ |
| M-06 | medium | logic-inference | ❌ |

---

## 詳細分析

### M-01: Supply 函數未檢查 market maxDeposit

**問題**：當 SiloVault 將資金存入多個底層 ERC4626 vault 時，未檢查各 vault 的 `maxDeposit` 限制。

**場景**：
- Vault 1 有 5,000 可存空間
- Vault 2 有 5,000 可存空間
- 用戶嘗試存入 10,000
- 函數嘗試將全部 10,000 存入 Vault 1 → revert

**漏洞程式碼**：
```solidity
function _supplyERC4626(uint256 _assets) internal virtual {
    for (uint256 i; i < supplyQueue.length; ++i) {
        IERC4626 market = supplyQueue[i];
        uint256 supplyCap = config[market].cap;
        // ...
        uint256 toSupply = UtilsLib.min(
            UtilsLib.zeroFloorSub(supplyCap, supplyAssets),
            _assets
        );
        // ❌ 未檢查 market.maxDeposit()
        try market.deposit(toSupply, address(this)) {
            // ...
        } catch {}
    }
}
```

**修復**：
```solidity
toSupply = Math.min(market.maxDeposit(address(this)), toSupply);
```

**教訓**：整合 ERC4626 時，必須同時考慮內部 cap 和外部 maxDeposit 限制。

---

### M-02: transfer 時 reward 計算錯誤

**問題**：`_accrueFee()` 會 mint 新 shares 給 feeRecipient，增加 `totalSupply()`。
- `deposit()/withdraw()` 會先呼叫 `_accrueFee()` 再計算 rewards
- `transfer()/transferFrom()` 直接呼叫 `_update()` → `_claimRewards()`，跳過 `_accrueFee()`

**影響**：transfer 時使用舊的 totalSupply 計算 rewards，導致分配不一致。

**漏洞程式碼**：
```solidity
function _update(address _from, address _to, uint256 _value) internal virtual override {
    // ❌ 缺少 _accrueFee()
    _claimRewards();  // 使用未更新的 totalSupply
    super._update(_from, _to, _value);
}
```

**修復**：在 `_update()` 開頭加入 `_updateLastTotalAssets(_accrueFee())`

---

### M-03: 無法移除 revert on zero approval 的 market

**問題**：移除 market 需要將 cap 設為 0，這會觸發 `forceApprove(market, 0)`。
某些 token（如 BNB）會在 approve(0) 時 revert。

**影響**：
- 無法移除這些 market
- 因為 `MAX_QUEUE_LENGTH` 限制，無法新增新 market

**修復**：將預設 approveValue 改為 1 而非 0
```solidity
- uint256 approveValue;
+ uint256 approveValue = 1;
```

**教訓**：處理 ERC20 token 時需考慮 weird token 行為。

---

### M-04: 缺少 slippage 和 deadline 保護

**問題**：`deposit()`、`withdraw()`、`redeem()` 都沒有：
- slippage 保護（minShares / minAssets）
- deadline 參數

**風險**：
- 多 vault 分配過程中價格變動
- 交易在 mempool 中延遲執行
- `_accrueFee()` 改變 shares/assets 換算率

---

### M-05: feeShares mint 順序導致獎勵分配錯誤

**問題**：Rewards 在 mint feeShares **之前**分配，導致 feeRecipient 獲得 shares 但沒有對應的 rewards。

**程式碼流程**：
```solidity
function _claimRewards() internal virtual {
    // 1. 分配 rewards（使用當前 totalSupply）
    // 2. 之後才 mint feeShares（增加 totalSupply）
}
```

**結果**：現有股東獲得過多 rewards，feeRecipient 被稀釋。

## 關鍵不變量（Invariants）

### ERC4626 Vault Aggregator Invariants

1. **Cap 一致性**：`balanceTracker[market] <= config[market].cap`
2. **資產守恆**：`totalAssets() == Σ market.balanceOf(this).convertToAssets()`
3. **Queue 完整性**：withdrawQueue 包含所有 enabled markets
4. **Approval 安全**：removed market 的 approval 應該 ≤ 1 wei
5. **Fee 同步**：任何改變 shares 的操作前，必須先 `_accrueFee()`
6. **Reward 公平**：rewards 分配時的 totalSupply 必須包含 feeShares

## Prompt 模板

### ERC4626 整合審計

```
我正在審計一個 ERC4626 Vault Aggregator，它將資金分配到多個底層 ERC4626 vault。

請檢查以下整合問題：

1. **Deposit 路徑**
   - 是否檢查每個底層 vault 的 maxDeposit()?
   - 如果某個 vault 滿了，是否正確跳到下一個?
   - 分配邏輯是否有 off-by-one 或溢出風險?

2. **Withdraw 路徑**
   - 是否檢查每個 vault 的 maxWithdraw()?
   - 如果某個 vault 流動性不足，是否正確處理?
   - 是否有可能卡住用戶資金?

3. **Share/Asset 換算**
   - 在多 vault 情況下，convertToShares/convertToAssets 是否準確?
   - fee accrual 是否在正確時機更新?

4. **Market 管理**
   - 新增/移除 market 是否有 edge case?
   - approval 管理是否考慮 weird token?

[貼上相關程式碼]
```

### Reward 分配審計

```
這是一個有 reward 分配機制的 ERC4626 vault。請檢查：

1. **totalSupply 同步**
   - 任何改變 shares 的操作（mint/burn/transfer）前，rewards 計算用的 totalSupply 是否正確?
   - fee shares mint 和 reward 分配的順序是否正確?

2. **Reward 計算公平性**
   - 新用戶是否能獲得不屬於他們時期的 rewards?
   - 舊用戶是否能避免稀釋?

3. **時序問題**
   - deposit-withdraw 同區塊操作是否有套利空間?
   - transfer 操作是否正確處理 rewards?

[貼上 reward 相關程式碼]
```

## 學到的教訓

1. **Fork 審計重點**：比較原版（Morpho）和修改版的差異，新增功能是高風險區
2. **ERC4626 整合**：必須同時考慮內部邏輯和外部 vault 的限制
3. **Weird ERC20**：處理 token 操作時，考慮 revert on zero、fee on transfer 等邊緣情況
4. **狀態同步**：涉及 totalSupply/totalAssets 的操作，注意更新順序
5. **獎勵系統**：mint/burn 順序會影響獎勵分配的公平性

## 相關漏洞模式

- `vulnerability-patterns/token/zero-approval-revert.md`
- `vulnerability-patterns/erc4626/max-deposit-check.md`
- `vulnerability-patterns/rewards/fee-share-ordering.md`

## 相關協議類型

- `protocol-patterns/erc4626-aggregator/invariants.md`
