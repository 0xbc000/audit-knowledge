# Panoptic - Code4rena April 2024

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Code4rena |
| **獎金池** | $120,000 USDC |
| **審計時間** | 2024-04-01 ~ 2024-04-22 |
| **協議類型** | Perpetual Options / DeFi Derivatives |
| **原始碼** | [GitHub](https://github.com/code-423n4/2024-04-panoptic) |
| **報告** | [C4 Report](https://code4rena.com/reports/2024-04-panoptic) |
| **程式碼行數** | 4,921 nSLOC |

## 協議概述

Panoptic 是一個無許可的永續期權交易協議，建立在任何 Uniswap V3 pool 之上。協議特點：
- 非託管（non-custodial）
- 無對手方風險
- 即時結算
- 全時全額抵押

### 核心架構

1. **SemiFungiblePositionManager (SFPM)** - 協議引擎，管理複雜多腿 Uniswap 倉位
2. **CollateralTracker** - ERC4626 vault，管理抵押品和保證金計算
3. **PanopticPool** - 協議指揮中心，協調所有交互
4. **PanopticFactory** - 部署新 pool

### 關鍵角色
- **Panoptic Liquidity Providers (PLPs)** - 存入 token 供賣方借用
- **Option Sellers** - 向 Uniswap 存入流動性
- **Option Buyers** - 從 Uniswap 移除流動性
- **Liquidators** - 清算不健康帳戶
- **Force Exercisors** - 強制執行價外期權

## 漏洞摘要

| ID | 嚴重度 | 標題 | 類型 |
|----|--------|------|------|
| H-01 | High | SettleLongPremium 應該扣除 premium 卻加了 | 業務邏輯 |
| H-02 | High | CollateralTracker overflow 允許免費 mint shares | 整數溢出 |
| M-01 | Medium | PanopticFactory 使用 spot price 部署（可操控） | 價格操控 |
| M-02 | Medium | _validatePositionList 未檢查重複 tokenId | 驗證繞過 |
| M-03 | Medium | CREATE2 地址碰撞可掏空 pool | 地址碰撞 |
| M-04 | Medium | liquidity spread 檢查邏輯錯誤 | 驗證邏輯 |
| M-05 | Medium | fee < 0.01% 時協議無法收手續費 | 精度問題 |
| M-06 | Medium | _updateSettlementPostBurn 未正確減少 grossPremiumLast | 狀態更新 |
| M-07 | Medium | burn 時 validate 應在 flip isLong 之前 | 執行順序 |
| M-08 | Medium | haircutPremia 中 chunkKey 計算錯誤（用 leg 0） | 索引錯誤 |
| M-09 | Medium | removedLiquidity 可溢出 uint128 | 整數溢出 |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 | high | code-confirmed | ✅ |
| H-02 | high | code-confirmed | ✅ |
| M-01 | medium | logic-inference | ❌ |
| M-02 | medium | code-confirmed | ❌ |
| M-03 | medium | logic-inference | ❌ |
| M-04 | medium | code-confirmed | ❌ |
| M-05 | medium | logic-inference | ❌ |
| M-06 | medium | code-confirmed | ❌ |
| M-07 | medium | logic-inference | ❌ |
| M-08 | medium | code-confirmed | ❌ |
| M-09 | medium | code-confirmed | ❌ |

---

## High Risk 詳細分析

### H-01: SettleLongPremium 加法方向錯誤 ⭐

**問題**：`settleLongPremium` 應該從 long option holder 帳戶**扣除** premium，但實際卻**加了**。

**漏洞程式碼**：
```solidity
// realizedPremia 是正數
LeftRightSigned realizedPremia = LeftRightSigned
    .wrap(0)
    .toRightSlot(int128(int256((accumulatedPremium.rightSlot() * liquidity) / 2 ** 64)))
    .toLeftSlot(int128(int256((accumulatedPremium.leftSlot() * liquidity) / 2 ** 64)));

// 傳給 exercise()，但 realizedPremia 應該是負數才會扣錢
s_collateralToken0.exercise(owner, 0, 0, 0, realizedPremia.rightSlot());
```

在 `exercise()` 中：
```solidity
int256 tokenToPay = -realizedPremium;
// 如果 realizedPremium > 0，tokenToPay < 0，用戶會被 mint shares！
if (tokenToPay > 0) {
    // burn tokens from user
} else if (tokenToPay < 0) {
    // mint tokens to user ← 錯誤發生在這
}
```

**影響**：Long option holders 本該付 premium，結果反而收到錢。

**修復**：傳入 `realizedPremia` 前取負值。

---

### H-02: CollateralTracker 整數溢出 ⭐

**問題**：`mint()` 函數的 `previewMint()` 在 unchecked block 中計算 `shares * DECIMALS`，可溢出。

**漏洞程式碼**：
```solidity
function previewMint(uint shares) public view returns (uint assets) {
    unchecked {
        // ❌ shares * DECIMALS 可溢出
        assets = Math.mulDivRoundingUp(
            shares * DECIMALS,
            totalAssets(),
            totalSupply * (DECIMALS - COMMISSION_FEE)
        );
    }
}
```

**攻擊**：
```solidity
uint shares = type(uint).max / 10000 + 1;
// shares * DECIMALS 溢出，assets 變得非常小
collateralToken.mint(shares, attacker);
// 攻擊者用極少的 assets 獲得大量 shares
```

**影響**：免費 mint 大量 shares，可提走所有抵押品。

**修復**：移除 unchecked block，或在 `maxMint()` 中正確限制。

---

## Medium Risk 詳細分析

### M-01: PanopticFactory 使用 spot price

**問題**：`deployNewPool` 使用 `slot0()` 的 spot price 計算初始流動性，可被閃電貸操控。

```solidity
(uint160 currentSqrtPriceX96, , , , , , ) = v3Pool.slot0();
// 用 spot price 計算流動性
fullRangeLiquidity = uint128(
    Math.mulDiv96RoundingUp(FULL_RANGE_LIQUIDITY_AMOUNT_WETH, currentSqrtPriceX96)
);
```

**影響**：部署者可能損失比預期更多的 token。

---

### M-02: 重複 tokenId 繞過 solvency 檢查

**問題**：`_validatePositionList` 使用 XOR hash，且長度欄位只有 8 bits（會溢出）。

攻擊者可加入 256 個相同 tokenId，hash 相同但 premium 重複計算。

```solidity
// 256 個相同 tokenId 的 hash 等於 0 個
Hash(key0, key1, key2) == Hash(key0, key1, key2, key0, key0, ..., 256個 key0)
```

**影響**：不溶帳戶可 mint/burn options。

---

### M-03: CREATE2 地址碰撞攻擊

**問題**：`salt` 由用戶控制，攻擊者可暴力搜索碰撞。

**攻擊流程**：
1. 找到 PanopticPool 地址與攻擊合約地址碰撞
2. 部署攻擊合約到該地址，設 approval，然後 `selfdestruct`
3. 部署 PanopticPool 到同地址
4. 利用之前設的 approval 提走所有資金

**可行性**：BTC 網路算力可在 31 分鐘內完成 2^80 次 hash。

---

### M-04: liquidity spread 驗證缺陷

**問題**：當 `netLiquidity == 0` 時跳過檢查，但若 `totalLiquidity > 0`，買方可不付 premium。

```solidity
if (netLiquidity == 0) return;  // ❌ 應該檢查 totalLiquidity
```

---

### M-05: 低 fee pool 無法收手續費

**問題**：`fee / 100` 會在 fee < 100 (0.01%) 時變成 0。

```solidity
_poolFee = fee / 100;  // fee = 50 (0.005%) → _poolFee = 0
s_ITMSpreadFee = (ITM_SPREAD_MULTIPLIER * _poolFee) / DECIMALS;  // = 0
```

**背景**：Uniswap 治理可能新增更低費率 tier。

---

### M-06: grossPremiumLast 狀態不同步

**問題**：`_updateSettlementPostBurn` 只在 `legPremia != 0` 時更新 `s_grossPremiumLast`。

同區塊 mint 再 burn，`legPremia == 0`，但 `totalLiquidity` 已變化。

```solidity
if (LeftRightSigned.unwrap(legPremia) != 0) {
    // 只有這裡才更新 s_grossPremiumLast
    // 但 totalLiquidity 已經變了！
}
```

---

### M-07: validate 應在 flipToBurnToken 之前

**問題**：burn 時先 flip `isLong` bits，再 validate，但有些 defined risk position 的驗證依賴原始 `isLong` 值。

```solidity
if (isBurn) {
    tokenId = tokenId.flipToBurnToken();  // 先 flip
}
tokenId.validate();  // 再 validate → 可能 revert
```

**影響**：某些倉位無法 burn。

---

### M-08: haircutPremia 中的 hardcoded index

**問題**：迴圈中用 `leg` 遍歷所有腿，但 `chunkKey` 計算永遠用 index 0。

```solidity
for (uint256 leg = 0; leg < tokenId.countLegs(); ++leg) {
    bytes32 chunkKey = keccak256(abi.encodePacked(
        tokenId.strike(0),   // ❌ 應該是 leg
        tokenId.width(0),    // ❌ 應該是 leg  
        tokenId.tokenType(0) // ❌ 應該是 leg
    ));
}
```

**影響**：`settledTokens` 只更新第一腿，seller 損失 premium。

---

### M-09: removedLiquidity 溢出

**問題**：註釋說 "can't overflow"，但重複 mint short + long 可使 `removedLiquidity` 溢出 `uint128`。

```solidity
unchecked {
    // we can't remove more liquidity than we add in the first place, so this can't overflow
    removedLiquidity += chunkLiquidity;  // ❌ 實際可以溢出
}
```

---

## 關鍵不變量

### Perpetual Options Protocol Invariants

1. **Solvency**：`collateral >= required_margin` 對所有帳戶成立
2. **Premium 方向**：buyers 付錢給 sellers，不能反過來
3. **流動性守恆**：`addedLiquidity >= removedLiquidity`
4. **Position Hash**：`hash(positionList) == s_positionsHash[account]`
5. **Unique Positions**：positionList 不包含重複 tokenId

## 學到的教訓

1. **unchecked 很危險**：H-02, M-09 都是 unchecked 中的溢出
2. **XOR hash 可碰撞**：M-02 用 256 次 XOR 回到原點
3. **CREATE2 + selfdestruct**：Dencun 後仍可在同 tx 內 selfdestruct
4. **Hardcoded index**：M-08 是典型的 copy-paste 錯誤
5. **整數除法精度**：M-05 fee/100 在低值時歸零
6. **執行順序重要**：M-07 先 validate 再 flip

## 相關漏洞模式

- `vulnerability-patterns/math/unchecked-overflow.md`
- `vulnerability-patterns/business-logic/comparison-operator-inversion.md`
- `vulnerability-patterns/access-control/create2-collision.md`
- `vulnerability-patterns/validation/hash-collision.md`

## 相關協議類型

- `protocol-patterns/perpetual-options/invariants.md`
