# Business Logic Audit Checklist

> 快速參考版 - 找 Critical 業務邏輯漏洞

---

## 🧮 數字驗證（每個核心函數必做）

```
□ 選 3 組具體數字跑一遍
  - 正常情況: (100, 10, 5)
  - 邊界情況: (1, 1, 1) 
  - 極端情況: (0, MAX, 很小的數)

□ 手算結果 vs 代碼結果
□ 問：「這個數字合理嗎？」
```

### 數字驗證速查

| 場景 | 測試值 | 問題 |
|------|--------|------|
| 百分比 | 0%, 1%, 99%, 100%, 101% | 超過 100% 怎辦？ |
| 費用 | 0 fee, 100% fee | 費用比本金大？ |
| 分配 | 1 recipient, 100 recipients | 總和 = 100%？ |
| 價格 | $0.0001, $1, $100000 | 極端價格處理？ |
| 數量 | 0, 1, 1e18, 1e36 | 溢出？精度？ |

---

## 🔒 不變量檢查

### 通用不變量
```
□ sum(parts) == total
□ user_balance <= total_balance  
□ fees_collected <= volume * fee_rate
□ shares * price >= underlying_value (no free money)
```

### 協議特定
```
Lending:
□ collateral * LTV >= debt (always)
□ totalDeposits >= totalBorrows
□ interest_accrued > 0 when time passes

DEX:
□ k 值只增不減（fees）
□ 無套利（arb opportunities = bug）

Vault:
□ deposit X → withdraw >= X (minus fees)
□ share price 只漲不跌（正常情況）

Staking:
□ claim <= entitled
□ sum(claimed) <= total_rewards
```

---

## 🎯 攻擊者視角

### 5 秒檢查
```
□ 能 0 成本獲利嗎？
□ 能閃電貸操縱什麼？
□ 能自我交易獲利嗎？
□ 能繞過任何費用嗎？
□ 能重複領獎勵嗎？
```

### 攻擊模式
```
□ 首次存款者優勢
□ 最後提款者劣勢
□ 清算者過度獎勵
□ 治理攻擊
□ 價格操縱 → 清算
□ 時間操縱（PoA chains）
```

---

## 🔄 狀態轉換

```
□ 畫出主要狀態
□ 每個轉換需要什麼條件？
□ 能跳過某個狀態嗎？
□ 能回到不該回的狀態嗎？
□ 卡在某狀態出不來？
```

---

## ⚡ 快速定位高風險區

### 代碼特徵
```solidity
// 🚨 高風險 - 必須數字驗證
for (...) { weight = X; }     // 迴圈中設相同值
total = single_value;         // total 不是 sum
share = a / b;                // 除法 = 精度損失
percent = x * 100 / y;        // 百分比計算
reward = balance * rate;      // 獎勵計算
```

### 函數特徵
```
🚨 distribute*()  - 分配邏輯
🚨 calculate*()   - 計算邏輯  
🚨 update*Weight/Share/Rate() - 比例更新
🚨 liquidate*()   - 清算邏輯
🚨 claim*()       - 領取邏輯
```

---

## 📝 發現記錄模板

```
## [BL-XX] 標題

**一句話：** 因為 [原因]，導致 [結果]

**數字證明：**
- 輸入: a=100, b=3
- 預期: 33.33 each
- 實際: 100 each
- 問題: 300% > 100%

**影響：** [誰損失多少錢]

**修復：** [一行代碼改動]
```

---

## 🎯 記住

```
1. 不要相信「看起來對」→ 用數字驗證
2. 找出不變量 → 嘗試打破它
3. 當攻擊者 → 「怎麼用最少成本獲最大利？」
4. 70% 靠 pattern，30% Critical 靠這個
```
