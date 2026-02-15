# ERC4626 Vault Aggregator Invariants

## 協議概述

ERC4626 Vault Aggregator（又稱 Meta Vault）將用戶資金分配到多個底層 ERC4626 vault，
以優化收益或分散風險。代表項目：Morpho Vault、Silo Vault、Yearn V3。

## 核心不變量

### 1. 資產守恆

```
totalAssets() == idle_balance + Σ underlying_vault[i].convertToAssets(shares_held[i])
```

- Aggregator 的 totalAssets 必須等於閒置資金加上所有底層 vault 的資產
- 考慮利息累積、fee deduction

### 2. Supply Cap 一致性

```
∀ market: actual_deposited[market] <= config[market].cap
∀ market: internal_tracker[market] <= config[market].cap
```

- 實際存入量不超過設定的 cap
- 內部追蹤器與實際餘額一致

### 3. Queue 完整性

```
∀ enabled_market: market ∈ withdrawQueue
|supplyQueue| <= MAX_QUEUE_LENGTH
|withdrawQueue| <= MAX_QUEUE_LENGTH
```

- 所有啟用的 market 都在 withdrawQueue 中
- Queue 長度不超過限制

### 4. Approval 安全性

```
∀ active_market: approval[market] == type(uint256).max || approval[market] > 0
∀ removed_market: approval[market] <= dust_amount (e.g., 1 wei)
```

- 活躍 market 有足夠 approval
- 移除的 market approval 接近 0

### 5. Fee 同步性

```
Before any share-changing operation:
  _accrueFee() must be called
  OR operation must not affect fee calculation
```

- 任何影響 shares 的操作前，必須先更新 fee
- totalSupply 必須反映當前 fee shares

### 6. Deposit/Withdraw 可用性

```
If totalSuppliable > 0:
  deposit(amount <= totalSuppliable) should NOT revert (unless paused)
  
If totalWithdrawable > 0:
  withdraw(amount <= totalWithdrawable) should NOT revert (unless paused)
```

- 如果有可存空間，deposit 不應失敗
- 如果有流動性，withdraw 不應失敗

## 常見攻擊向量

### 1. Max Deposit 不一致

**問題**：Aggregator 計算可存金額時只考慮內部 cap，忽略底層 vault 的 maxDeposit()

**檢查**：
```solidity
// 錯誤
uint256 toSupply = min(cap - deposited, _assets);

// 正確
uint256 toSupply = min(
    min(cap - deposited, _assets),
    market.maxDeposit(address(this))
);
```

### 2. Queue 操作導致資金卡住

**問題**：更新 queue 時移除有餘額的 market，導致用戶無法取款

**檢查**：
```solidity
function removeMarket(market) {
    require(balanceOf[market] == 0, "Market has balance");
    // 或者先自動 withdraw
}
```

### 3. 底層 Vault Exploit 連鎖效應

**問題**：某個底層 vault 被攻擊，影響整個 aggregator

**緩解**：
- 設定每個 market 的 cap 限制最大損失
- 使用內部 balance tracker 而非直接讀取底層 vault

### 4. Share 價格操控

**問題**：通過操控底層 vault 的 share 價格，影響 aggregator 的 totalAssets

**檢查**：
- 是否有 minimum deposit 防止首次存款攻擊
- share 價格是否有合理邊界檢查

## 審計 Checklist

### Deposit 流程
- [ ] 是否檢查每個底層 vault 的 `maxDeposit()`？
- [ ] 如果某 vault 滿了，是否正確分配到下一個？
- [ ] 分配失敗時是否有 fallback（idle balance）？
- [ ] 是否更新內部 balance tracker？

### Withdraw 流程
- [ ] 是否檢查每個 vault 的 `maxWithdraw()`？
- [ ] 是否按 withdrawQueue 順序提取？
- [ ] 流動性不足時是否正確 revert（而非部分提取）？
- [ ] 是否更新內部 balance tracker？

### Market 管理
- [ ] 新增 market 是否驗證資產一致性（same underlying）？
- [ ] 移除 market 是否先清空餘額？
- [ ] approval 管理是否考慮 weird token（revert on zero）？
- [ ] cap 更新是否有 timelock？

### Fee/Reward 機制
- [ ] fee accrual 是否在正確時機？
- [ ] totalSupply 用於計算時是否已包含 fee shares？
- [ ] reward 分配順序是否公平？

### 整合風險
- [ ] 底層 vault pause 時的行為？
- [ ] 底層 vault upgrade 時的兼容性？
- [ ] 底層 vault 被攻擊時的損失隔離？

## 相關案例

- **Silo Finance 2025** - maxDeposit 未檢查、fee share 順序問題
- **Morpho Blue** - 原版設計參考
- **Yearn V3** - 類似的 aggregator 架構
