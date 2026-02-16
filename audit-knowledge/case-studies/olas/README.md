# Autonolas (OLAS) Tokenomics Audit - 2026

> 一個自建 TWAP Oracle 數學錯誤的經典案例

## 概述

| 項目 | 詳情 |
|------|------|
| 協議 | Autonolas (OLAS) |
| 類型 | Tokenomics / Liquidity Management |
| 審計時間 | 2026-01-31 |
| 關鍵發現 | TWAP 計算數學錯誤 |
| 最高嚴重性 | Critical |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| C-01 | high | code-confirmed | ✅ |
| H-01 | high | code-confirmed | ✅ |

---

## 關鍵 Findings

### C-01: TWAP 永遠等於現貨價格 🔴 Critical

**檔案:** `UniswapPriceOracle.sol`

**問題代碼:**
```solidity
uint256 cumulativePrice = cumulativePriceLast + (tradePrice * elapsedTime);
uint256 timeWeightedAverage = (cumulativePrice - cumulativePriceLast) / elapsedTime;
```

**數學證明:**
```
設 C = cumulativePriceLast, P = tradePrice, T = elapsedTime

TWAP = ((C + P×T) - C) / T
     = (P × T) / T
     = P

結論: TWAP ≡ 現貨價格 (歷史數據被完全消除)
```

**影響:**
- TWAP 保護完全失效
- Flash loan 價格操縱變得 trivial
- `validatePrice()` 永遠返回 true

**教訓:**
1. 任何數學公式都要做代數簡化驗證
2. 不要假設「看起來複雜」的代碼就是正確的
3. 自建 Oracle 風險極高，應優先使用經過驗證的解決方案

---

### H-01: DEX Swap 無滑點保護 🟠 High

**檔案:** `BuyBackBurnerUniswap.sol`

**問題代碼:**
```solidity
// V3 路徑
amountOutMinimum: 1,

// V2 路徑
swapExactTokensForTokens(amount, 0, path, ...);
```

**影響:**
- 每筆 swap 都可被三明治攻擊
- 最高可損失 100% 交易價值

**教訓:**
1. `amountOutMin` 必須基於 Oracle 計算
2. 永遠不要設為 0 或 1

---

## 發現方法

### 成功的方法

1. **代數驗證** — 手動展開 TWAP 公式發現消除問題
2. **Grep 搜索** — `amountOutMinimum:\s*[01]` 找到滑點問題
3. **Foundry PoC** — 用測試證明 10x 價格操縱通過驗證

### 自動化工具對比

| 工具 | 發現 C-01? | 評級 |
|------|------------|------|
| V12 Scanner | ✅ | Qa (嚴重低估) |
| 4naly3er | ❌ | — |
| 我們的方法 | ✅ | Critical (正確) |

**結論:** 自動化工具找到了問題但嚴重低估。代數驗證是發現此類漏洞的關鍵。

---

## 適用的漏洞模式

- [Oracle / TWAP Implementation Errors](../../vulnerability-patterns/oracle/twap-implementation-errors.md)
- [DEX / Slippage Protection](../../vulnerability-patterns/dex/slippage-protection.md)

## PoC 位置

- `/Users/billyc/clawd/olas-audit/poc/test/C01_TwapBypass.t.sol`

## 完整報告

- [ClawdEva Audit Report v2](../../olas-audit/clawdeva-audit-findings-2026-01-31-v2.md)

---

*Case study added: 2026-01-31*
