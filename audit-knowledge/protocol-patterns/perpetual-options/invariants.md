# Perpetual Options Protocol Invariants

## 協議概述

永續期權協議（如 Panoptic）允許在 AMM（如 Uniswap V3）之上交易無到期日的期權。
核心機制是通過添加/移除 AMM 流動性來創建 short/long 期權倉位。

## 核心概念

### 倉位類型
- **Short Position（賣方）**：向 AMM 添加流動性，賺取 premium
- **Long Position（買方）**：從 AMM 移除流動性，支付 premium

### Premium 計算
- Premium = 被移除流動性本應產生的 LP fees × spread multiplier
- Premium 從 buyer 流向 seller

## 核心不變量

### 1. Solvency（償付能力）

```
∀ account:
  collateral_balance[account] >= margin_requirement[account]
  
margin_requirement = f(position_size, price_distance, utilization)
```

- 任何時刻，帳戶抵押品必須 ≥ 保證金要求
- 不滿足時可被清算

### 2. Premium 方向性

```
premium_flow: buyers → sellers

In settleLongPremium:
  buyer.collateral -= premium
  NOT: buyer.collateral += premium
```

- Premium 必須從 long position（買方）流向 short position（賣方）
- 方向錯誤會導致協議虧損

### 3. 流動性守恆

```
∀ liquidity_chunk:
  total_liquidity >= removed_liquidity
  added_liquidity - removed_liquidity >= 0
```

- 不能移除比添加更多的流動性
- removed_liquidity 不應溢出

### 4. Position Hash 完整性

```
hash(positionIdList) == s_positionsHash[account]

Where hash uses XOR and length counter:
  hash = XOR(hash(tokenId_i)) | (length << 248)
```

- 傳入的 position list 必須匹配存儲的 hash
- 注意 XOR 碰撞和長度溢出

### 5. Position 唯一性

```
∀ i, j where i ≠ j:
  positionIdList[i] != positionIdList[j]
```

- Position list 不應包含重複 tokenId
- 重複會導致 premium 重複計算

### 6. Leg 一致性

```
∀ leg in position:
  if leg.riskPartner != leg.index:
    legs[leg.riskPartner].riskPartner == leg.index
    legs[leg.riskPartner].asset == leg.asset
    legs[leg.riskPartner].optionRatio == leg.optionRatio
```

- 風險對沖的腿必須互相引用
- 必須有相同的資產和比例

## 常見攻擊向量

### 1. Solvency 繞過

**手法**：利用 position list 驗證漏洞繞過 solvency 檢查
- 重複 tokenId 使 premium 多次計入抵押品
- 利用 hash 碰撞偽造有效 position list

**檢測**：驗證 position list 長度和唯一性

### 2. Premium 方向錯誤

**手法**：找到 premium 計算或支付邏輯的符號錯誤
- 加法應該是減法
- 正數應該是負數

**檢測**：追蹤資金流向，確認 buyer 付款、seller 收款

### 3. 整數溢出

**手法**：利用 unchecked block 或大數輸入觸發溢出
- shares × DECIMALS 溢出
- removedLiquidity 溢出

**檢測**：審查所有 unchecked block，驗證邊界假設

### 4. 執行順序問題

**手法**：利用狀態修改和驗證的順序問題
- 先 flip 再 validate（應反過來）
- 先分配 reward 再 mint fee shares

**檢測**：畫出操作的狀態變化圖

## 審計 Checklist

### Premium 機制
- [ ] Premium 從 buyer 流向 seller？
- [ ] settleLongPremium 扣款方向正確？
- [ ] premium accumulator 更新時機正確？
- [ ] 所有腿的 premium 都計算了（不只 leg 0）？

### Solvency 檢查
- [ ] position list 驗證防止重複？
- [ ] hash 長度欄位不會溢出？
- [ ] 所有改變 position 的路徑都檢查 solvency？

### 整數安全
- [ ] unchecked block 的假設有效？
- [ ] 大輸入值不會導致溢出？
- [ ] 除法不會因小分母而異常？

### 狀態更新
- [ ] 狀態更新順序正確？
- [ ] 條件更新不會跳過必要的同步？
- [ ] burn 和 mint 對稱處理？

### 外部整合
- [ ] 使用 TWAP 而非 spot price？
- [ ] 處理 Uniswap fee tier 的邊緣情況？
- [ ] CREATE2 salt 不可被濫用？

## 相關案例

- **Panoptic 2024** - 11 個漏洞，涵蓋 premium 方向、溢出、驗證繞過
