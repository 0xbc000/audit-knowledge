# 永續合約 DEX - 核心不變量 (Invariants)

## 概述

永續合約 DEX 通常包含以下核心組件：
- **Trading Engine**: 處理開倉、平倉、清算
- **Market Making / Liquidity Engine**: 管理 LP 資金池
- **Oracle**: 價格來源
- **Margin System**: 保證金管理

## 必須維持的不變量

### 1. 償付能力 (Solvency)

```solidity
// LP Vault 總資產必須能覆蓋所有債務
assert(vault.totalAssets >= vault.totalLiabilities)

// 更精確的版本（考慮未實現 P&L）
assert(vault.totalAssets >= vault.realizedDebt + vault.unrealizedDebt)
```

**違反後果**: 協議無法履行對 trader 的支付義務

### 2. 信用委託正確性 (Credit Delegation)

```solidity
// 所有 market 收到的 credit 總和 <= vault 總資產
assert(sum(market.delegatedCredit) <= vault.totalAssets)

// 權重分配正確
assert(sum(creditDelegation.weight) == vault.totalWeight)
// 或者
assert(sum(creditDelegation.share) == 100%)
```

**違反後果**: Over-leveraging，可能導致 insolvency

### 3. 保證金充足 (Margin Adequacy)

```solidity
// 每個 position 的保證金必須 >= 維持保證金
for each position:
    assert(position.margin >= position.maintenanceMarginRequired)
    
// 否則應該被清算
if (position.margin < position.maintenanceMarginRequired) {
    position.shouldBeLiquidatable = true
}
```

**違反後果**: 壞帳累積

### 4. P&L 結算正確性 (P&L Settlement)

```solidity
// 結算前後總資產守恆（手續費除外）
assert(totalAssetsAfter == totalAssetsBefore - fees)

// Trader 盈利 = LP 虧損（零和遊戲）
assert(traderPnL + lpPnL + protocolFees == 0)
```

**違反後果**: 資金憑空產生或消失

### 5. 債務結算方向正確 (Debt Settlement)

```solidity
// 結算後債務應該減少，不是增加
assert(debtAfterSettlement <= debtBeforeSettlement)

// 有債務時：賣資產換穩定幣
// 有餘額時：賣穩定幣換資產
if (debt > 0) sellAssetsForStable();
if (debt < 0) sellStableForAssets();
```

**違反後果**: 債務不減反增

### 6. Open Interest 限制

```solidity
// 市場 OI 不能超過上限
assert(market.openInterest <= market.maxOpenInterest)

// Skew 不能超過限制
assert(abs(market.longOI - market.shortOI) <= market.maxSkew)
```

**違反後果**: 風險敞口失控

### 7. Oracle 價格有效性

```solidity
// 價格必須在有效期內
assert(block.timestamp - oracle.lastUpdate <= maxStaleness)

// 價格必須在合理範圍
assert(oracle.price > 0)
assert(abs(oracle.price - twap) <= maxDeviation)
```

**違反後果**: 使用過期或被操縱的價格

## 審計檢查清單

### Vault / LP 相關
- [ ] Credit delegation 權重計算正確
- [ ] 債務分配按比例進行
- [ ] 結算邏輯方向正確
- [ ] 提款不會導致 insolvency
- [ ] Locked credit ratio 計算正確

### Trading 相關
- [ ] 保證金計算包含所有費用
- [ ] 清算條件正確
- [ ] P&L 計算精度足夠
- [ ] 無法開超過 OI 限制的倉位

### Oracle 相關
- [ ] Staleness 檢查存在
- [ ] 價格偏差檢查
- [ ] Sequencer uptime 檢查（L2）

### Access Control
- [ ] 只有授權地址能調用敏感函數
- [ ] Keeper 權限範圍適當
- [ ] Admin 操作有時間鎖

## 常見漏洞模式

| 模式 | 相關不變量 | 嚴重性 |
|------|-----------|--------|
| 權重分配錯誤 | #2 Credit Delegation | High |
| 結算方向反轉 | #5 Debt Settlement | High |
| Oracle 操縱 | #7 Oracle | Critical |
| Margin 計算錯誤 | #3 Margin | High |
| 清算條件錯誤 | #3 Margin | High |

## 參考案例
- [Zaros 2025-01](../case-studies/zaros-2025/)
- Perpetual Protocol audits
- GMX audits
- dYdX audits
