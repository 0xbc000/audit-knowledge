# Lending Protocol Invariants

## 核心 Invariants

### 1. 償付能力
```
∀ time t:
  total_collateral_value >= total_debt_value
  OR protocol has bad_debt mechanism
```

### 2. 利息計算
```
debt(t) = debt(0) × exchange_rate(t)
exchange_rate is monotonically increasing
interest_accrued > 0 when time_elapsed > 0 AND debt > 0
```

### 3. 清算可行性
```
∀ unhealthy_position:
  liquidation_tx MUST be executable
  liquidator_profit > gas_cost (incentive alignment)
  NO external dependency can block liquidation
```

### 4. 資產守恆
```
total_deposits = total_loans + available_liquidity + reserves
∀ user: shares_value ≈ deposited_value + accrued_interest - fees
```

### 5. 健康因子
```
health_factor = collateral_value × LTV / debt_value
if health_factor < 1: position is liquidatable
if health_factor >= safe_threshold: position is healthy
```

---

## 利率模型

### 典型公式
```
utilization = total_borrowed / total_supplied
borrow_rate = base_rate + utilization × slope
supply_rate = borrow_rate × utilization × (1 - reserve_factor)
```

### 跳躍利率模型 (Kink)
```
if utilization <= kink:
  borrow_rate = base + utilization × slope1
else:
  borrow_rate = base + kink × slope1 + (utilization - kink) × slope2
```

### 驗證點
- [ ] 利率隨 utilization 單調遞增
- [ ] reserve_factor 正確應用
- [ ] 利率更新時機正確

---

## 清算機制

### 健康清算
```
1. 驗證 position unhealthy
2. 計算可清算金額 (debt)
3. 計算應 seize 抵押品
4. 執行 debt repay + collateral seize
5. 驗證 liquidator 收益合理
```

### 常見漏洞
| 漏洞 | 描述 |
|------|------|
| 清算阻塞 | callback 拒絕接收 token |
| 過度清算 | seize 金額超過應得 |
| 清算無利可圖 | position 太小，gas > 收益 |
| 價格操縱 | Oracle 被操控時清算 |

### 設計建議
```solidity
// ✅ Pull 模式（不依賴用戶配合）
function liquidate(...) {
    // seize 抵押品到協議
    // 被清算者稍後自行領取（如果有剩餘）
}

// ❌ Push 模式（可被阻塞）
function liquidate(...) {
    // 直接轉帳給被清算者
    token.safeTransfer(user, amount);  // 可能 revert
}
```

---

## 重入保護

### 外部呼叫點
1. ERC20 transfer/transferFrom
2. ERC721/1155 safeTransfer (callback)
3. ETH 轉帳 (fallback/receive)
4. Oracle 查詢
5. 外部合約呼叫

### 正確順序
```
1. 檢查 (require)
2. 更新狀態
3. 外部呼叫
4. 事後驗證
```

### 常見錯誤
```solidity
// ❌ 先呼叫，後更新
token.transfer(user, amount);
balances[user] -= amount;

// ✅ 先更新，後呼叫
balances[user] -= amount;
token.transfer(user, amount);
```

---

## Oracle 安全

### 必要檢查
```solidity
(, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
require(price > 0, "Invalid price");
require(updatedAt >= block.timestamp - MAX_STALENESS, "Stale price");
require(price >= MIN_PRICE && price <= MAX_PRICE, "Price out of bounds");
```

### 多來源驗證
```solidity
uint256 chainlinkPrice = getChainlinkPrice();
uint256 twapPrice = getTwapPrice();
require(
    abs(chainlinkPrice - twapPrice) <= MAX_DEVIATION,
    "Price deviation too high"
);
```

---

## Bad Debt 處理

### 機制選項
1. **協議儲備金** - 從 reserve 中扣除
2. **社會化損失** - 所有 lender 分攤
3. **保險基金** - 獨立基金覆蓋
4. **清償激勵** - 支付獎勵給清償者

### 驗證點
- [ ] 誰可以標記 bad debt
- [ ] 標記後如何處理
- [ ] 清償激勵是否可被濫用
- [ ] 陣列/映射操作的邊界檢查

---

## 審計 Checklist

### 借款
- [ ] 借款前更新利率
- [ ] 健康因子檢查
- [ ] 借款上限檢查
- [ ] 事件正確發出

### 還款
- [ ] 利息計算正確
- [ ] 部分還款處理
- [ ] 還款金額驗證

### 清算
- [ ] 健康因子計算
- [ ] 清算金額限制
- [ ] 抵押品 seize 計算
- [ ] 無法被阻塞

### 存取款
- [ ] Share 計算正確
- [ ] 取款上限（流動性）
- [ ] Fee 扣除

---

## 相關案例

| 協議 | 類型 | 主要漏洞 |
|------|------|----------|
| Revert Lend | V3 Position Lending | Permit2、重入、權限 |
| Wise Lending | 標準 Lending | 重入保護繞過、Bad Debt |
| Size | Credit Market | Fee 計算、Dust Position |
| Sentiment V2 | Multi-Collateral | 清算溢出、黑名單 |
