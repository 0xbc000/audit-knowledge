# Sentiment V2 - Sherlock August 2024

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Sherlock |
| **獎金池** | $47,500 USDC |
| **審計時間** | 2024-08 |
| **協議類型** | Multi-Collateral Lending |
| **原始碼** | [GitHub](https://github.com/sherlock-audit/2024-08-sentiment-v2) |
| **Judging** | [GitHub](https://github.com/sherlock-audit/2024-08-sentiment-v2-judging) |

## 協議概述

Sentiment V2 是一個 **多抵押品借貸協議**：
- 用戶可以用多種資產作為抵押品
- 每個 Position 是獨立的智能合約
- 支援多種 Oracle（Chainlink, Redstone 等）

### 核心元件
- **Pool** - 借貸池
- **Position** - 用戶的抵押品容器（智能合約）
- **RiskModule** - 風險計算
- **PositionManager** - Position 管理

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| Liquidation over-seize | medium | code-confirmed | ❌ |
| USDC blacklist DoS | low | logic-inference | ❌ |
| Redstone Oracle | low | logic-inference | ❌ |

---

## 主要漏洞類型

基於 Judging repo 的 issues：

### 清算相關
- Liquidation 使用 `type(uint).max` 可 seize 過多資產
- USDC 黑名單地址導致清算失敗
- Bad debt 監控導致其他用戶損失

### Oracle 相關
- Redstone Oracle 價格驗證不足
- 價格操縱風險

### Position 相關
- Position 合約的資產轉移問題
- 利息分配操縱

---

## 清算漏洞分析

### Liquidation 過度 Seize

**問題**：使用 `type(uint).max` 作為 seize 金額時，可能拿走過多抵押品。

```solidity
function liquidate(
    address position,
    DebtData[] calldata debtData,
    AssetData[] calldata assetData
) external {
    // 如果 assetData.amt = type(uint).max
    // 可能 seize 超過應得的金額
}
```

**影響**：被清算者損失過多抵押品

### USDC 黑名單導致 DoS

**問題**：如果 Position 地址被 USDC 黑名單，清算時的轉帳會失敗。

```solidity
// 在清算流程中
IERC20(asset).transfer(receiver, amount);  // ❌ 如果 position 被黑名單則失敗
```

**影響**：無法清算 → 壞帳

---

## Multi-Collateral Lending Invariants

### 1. Position 隔離
```
∀ position:
  assets in position belong to position owner
  debt of position is responsibility of position owner
```

### 2. 抵押品價值計算
```
collateral_value = Σ(asset_amount × asset_price × collateral_factor)
```

### 3. 健康因子
```
health_factor = collateral_value / debt_value
if health_factor < 1:
  position is liquidatable
```

### 4. 清算公平性
```
seized_value ≈ debt_repaid × (1 + liquidation_bonus)
NOT: seized_value >> debt_repaid
```

---

## Sherlock 格式注意事項

### 目錄結構
```
sherlock-audit/2024-08-sentiment-v2/
├── protocol-v2/          # 主要合約
│   ├── src/
│   └── test/
└── README.md             # 協議說明

sherlock-audit/2024-08-sentiment-v2-judging/
├── 001.md ~ NNN.md       # 每個 issue 一個文件
├── invalid/              # 無效提交
└── README.md
```

### 如何閱讀 Sherlock 報告
1. 看 `judging` repo 的 issues
2. 有效 issues 在根目錄
3. 每個 `.md` 檔案是一個 finding
4. 重複的會被標記為 duplicate

---

## Position-Based Lending 特有風險

### 1. Position 合約安全
- Position 是獨立合約，可能有自己的漏洞
- 需要防止非法資產提取
- Callback 攻擊風險

### 2. 多抵押品複雜性
- 不同資產的價格波動
- Collateral factor 設定
- 清算優先順序

### 3. Oracle 多樣性
- 不同資產用不同 Oracle
- 價格同步問題
- Fallback 機制

---

## 審計 Checklist

### Position 合約
- [ ] 資產只能被授權方提取
- [ ] 不能通過 callback 重入
- [ ] 升級/銷毀邏輯安全

### 清算
- [ ] Seize 金額計算正確
- [ ] 特殊 token (黑名單、暫停) 處理
- [ ] 部分清算邏輯

### Oracle
- [ ] 每種 Oracle 的驗證邏輯
- [ ] 價格過期處理
- [ ] Fallback 策略

---

## 相關漏洞模式

- `vulnerability-patterns/lending/liquidation-overflow.md`
- `vulnerability-patterns/token/usdc-blacklist.md`
- `vulnerability-patterns/oracle/redstone-validation.md`
