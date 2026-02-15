# Size - Code4rena June 2024

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Code4rena |
| **獎金池** | ~$50,000 USDC |
| **審計時間** | 2024-06-10 ~ 2024-07-02 |
| **協議類型** | Credit Market (P2P Lending) |
| **原始碼** | [GitHub](https://github.com/code-423n4/2024-06-size) |
| **報告** | [C4 Report](https://code4rena.com/reports/2024-06-size) |
| **程式碼行數** | 32 contracts, 2,578 nSLOC |

## 協議概述

Size 是一個 **信用市場** 協議：
- 用戶可以買賣 credit positions
- 固定期限借貸
- 訂單簿式匹配

### 與傳統 Lending 的區別
| 傳統 Lending | Size Credit Market |
|--------------|-------------------|
| 池子模式 | P2P 訂單匹配 |
| 浮動利率 | 固定利率 |
| 隨時還款 | 固定到期日 |

### 核心概念
- **Credit** - 債權代幣化
- **Tenor** - 借貸期限
- **szaUSDC** - 協議內部計價 token

## 漏洞摘要

| ID | 嚴重度 | 標題 | 類型 |
|----|--------|------|------|
| H-01 | High | sellCreditMarket 手續費計算錯誤 | 費用計算 |
| H-02 | High | Fragmentation fee 未正確處理 | 費用計算 |
| H-03 | High | Credit 分割導致壞帳 | 邏輯錯誤 |
| H-04 | High | 清算價格計算錯誤 | 數學錯誤 |
| M-01 ~ M-13 | Medium | 各種中等問題 | 多種 |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 | high | code-confirmed | ✅ |
| H-02 | high | code-confirmed | ✅ |
| H-03 | medium | logic-inference | ❌ |
| H-04 | medium | code-confirmed | ❌ |

---

## High Risk 詳細分析

### H-01: Swap Fee 計算錯誤 ⭐

**問題**：當用指定 cash 數量賣出 credit 時，手續費計算公式錯誤。

**官方文檔公式**：
```
fee = cashAmountOut × swapFeePercent / (1 - swapFeePercent) + fragmentationFee
```

**實際實現**：
```solidity
// ❌ 錯誤實現
fees = Math.mulDivUp(cashAmountOut, swapFeePercent, PERCENT) + fragmentationFee;
```

**差異範例**：
- 賣出 credit 獲得 99.5 szaUSDC
- 正確手續費: 0.5 szaUSDC
- 實際手續費: 0.4975 szaUSDC
- 協議少收: 0.0025 szaUSDC

**影響**：協議持續損失手續費收入

---

### H-02: Fragmentation Fee 邊界處理

**問題**：當 credit 被分割成多個小部分時，fragmentation fee 的處理有問題。

```solidity
// 邊界情況
if (maxCashAmountOut >= state.feeConfig.fragmentationFee) {
    // 正常處理
} else {
    // ❌ 這個分支的處理有問題
}
```

---

### H-03: Credit 分割導致壞帳

**問題**：credit position 可以被分割到 `minCreditSize` 以下，導致清算不划算。

**攻擊**：
1. 借大額貸款
2. 分割成很多小 credit（每個低於清算閾值）
3. 違約
4. 清算者不願意清算（gas > 收益）
5. 壞帳累積

---

## Credit Market 特有 Invariants

### 1. 手續費一致性
```
∀ trade:
  actual_fee = calculated_fee (按文檔公式)
  protocol_revenue = Σ(fees)
```

### 2. Credit 總量守恆
```
total_credit_minted = total_credit_outstanding + total_credit_repaid
```

### 3. 最小 Position 大小
```
∀ credit_position:
  size >= minCreditSize
  OR position is being closed
```

### 4. 到期日邏輯
```
∀ credit:
  if (now > maturity):
    position can be liquidated
```

---

## Fee 計算常見錯誤

### 錯誤 1：分母分子混淆
```solidity
// ❌ 錯誤
fee = amount * feePercent / 100;

// ✅ 正確（如果 fee 從 amount 中扣除）
fee = amount * feePercent / (100 - feePercent);
```

### 錯誤 2：取整方向錯誤
```solidity
// ❌ 協議應該向上取整（多收）
fee = amount * feePercent / 100;

// ✅ 正確
fee = Math.mulDivUp(amount, feePercent, 100);
```

### 錯誤 3：固定費用 + 百分比費用
```solidity
// 順序很重要！
// 方案 A: 先算百分比，再加固定費用
fee = percentFee + fixedFee;

// 方案 B: 固定費用也計入百分比
fee = (amount + fixedFee) * percent / 100;
```

---

## 審計重點

### Credit/Debt Market
- [ ] 買賣 credit 的手續費計算
- [ ] Credit 分割/合併的邊界處理
- [ ] 到期日相關邏輯
- [ ] 訂單匹配的原子性

### 清算
- [ ] 部分清算 vs 全額清算
- [ ] 清算獎勵是否覆蓋成本
- [ ] 最小清算金額

---

## 相關漏洞模式

- `vulnerability-patterns/math/fee-calculation.md`
- `vulnerability-patterns/lending/dust-positions.md`
- `vulnerability-patterns/lending/maturity-handling.md`
