# Revert Lend - Code4rena March 2024

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Code4rena |
| **獎金池** | ~$45,000 USDC |
| **審計時間** | 2024-03-04 ~ 2024-03-15 |
| **協議類型** | Uniswap V3 Position Lending |
| **原始碼** | [GitHub](https://github.com/code-423n4/2024-03-revert-lend) |
| **報告** | [C4 Report](https://code4rena.com/reports/2024-03-revert-lend) |
| **程式碼行數** | 11 contracts, 3,214 nSLOC |
| **Mitigation Review** | ✅ 有 |

## 協議概述

Revert Lend 允許用戶將 **Uniswap V3 LP Position (NFT)** 作為抵押品進行借貸。

### 核心元件
- **V3Vault** - 主要借貸邏輯，ERC-4626 vault
- **V3Oracle** - 價格預言機（Chainlink + Uniswap TWAP）
- **InterestRateModel** - 利率模型
- **Transformers** - 管理抵押品的工具（AutoCompound, AutoRange 等）
- **V3Utils** - Position 操作工具

## 漏洞摘要

| ID | 嚴重度 | 標題 | 類型 |
|----|--------|------|------|
| H-01 | High | Permit2 未驗證 token 地址 | 輸入驗證 |
| H-02 | High | onERC721Received 重入攻擊 | 重入 |
| H-03 | High | transform() 未驗證 tokenId | 輸入驗證 |
| H-04 | High | V3Utils.execute() 無權限控制 | 權限控制 |
| H-05 | High | TWAP 負數 tick 未向下取整 | 數學錯誤 |
| H-06 | High | 惡意 onERC721Received 阻止清算 | DoS |
| M-01 | Medium | 繞過 collateral limit | 限制繞過 |
| M-02 | Medium | AutoRange gas griefing | DoS |
| M-03 | Medium | 無 minLoanSize 導致清算無利可圖 | 經濟激勵 |
| M-04 | Medium | 同區塊免息貸款 | 利率計算 |
| M-05 | Medium | setReserveFactor 未更新利息 | 狀態更新 |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 | high | code-confirmed | ✅ |
| H-02 | high | code-confirmed | ✅ |
| H-03 | high | code-confirmed | ✅ |
| H-04 | high | code-confirmed | ✅ |
| H-05 | high | code-confirmed | ✅ |
| H-06 | medium | logic-inference | ❌ |
| M-01 | medium | logic-inference | ❌ |
| M-02 | medium | logic-inference | ❌ |
| M-03 | medium | logic-inference | ❌ |
| M-04 | medium | code-confirmed | ❌ |
| M-05 | medium | code-confirmed | ❌ |

---

## High Risk 詳細分析

### H-01: Permit2 未驗證 Token 地址 ⭐

**問題**：`permit2.permitTransferFrom()` 未驗證 `permit.permitted.token` 是否等於 vault 的 asset。

```solidity
// ❌ 沒有驗證 token
(ISignatureTransfer.PermitTransferFrom memory permit, bytes memory signature) =
    abi.decode(params.permitData, ...);
permit2.permitTransferFrom(permit, ...);
```

**攻擊**：
1. 用任何垃圾 token 簽署 permit
2. Vault 接受為有效的 USDC 存款
3. 盜走 vault 中所有 USDC

**修復**：
```solidity
require(permit.permitted.token == asset, "V3Vault: invalid token");
```

---

### H-02: onERC721Received 重入攻擊

**問題**：`_cleanupLoan()` 在 `_updateAndCheckCollateral()` 之前執行，而 `_cleanupLoan()` 會呼叫 `safeTransferFrom` 觸發 callback。

```solidity
function onERC721Received(...) external {
    // 複製 debt 到新 token
    loans[tokenId] = Loan(loans[oldTokenId].debtShares);
    
    // ❌ 先 cleanup（包含 safeTransfer callback）
    _cleanupLoan(oldTokenId, ...);  // → 可重入
    
    // 後更新 collateral
    _updateAndCheckCollateral(tokenId, ...);
}
```

**攻擊**：
1. 透過 AutoRange 變換 position
2. 收到舊 NFT 時重入呼叫 `borrow()`
3. `_updateAndCheckCollateral` 被呼叫兩次
4. 操縱 `totalDebtShares`，阻止其他人借款

---

### H-03: transform() 未驗證 Calldata 中的 tokenId

**問題**：`transform()` 驗證 `tokenId` 參數的所有權，但未驗證 `data` calldata 中編碼的 tokenId。

```solidity
function transform(uint256 tokenId, address transformer, bytes calldata data) external {
    // ✅ 驗證 tokenId 所有權
    if (loanOwner != msg.sender && !transformApprovals[...]) revert;
    
    // ❌ 沒有驗證 data 中的 tokenId
    (bool success,) = transformer.call(data);  // data 可以包含任何 tokenId
}
```

**攻擊**：
1. 攻擊者在 vault 有自己的 position
2. 用自己的 tokenId 通過驗證
3. 但 data 中編碼別人的 tokenId
4. 操作別人批准給 AutoCompound 的 position

---

### H-04: V3Utils.execute() 無權限控制

**問題**：`V3Utils.execute()` 沒有驗證呼叫者是否為 NFT 所有者。

```solidity
function execute(uint256 tokenId, Instructions memory instructions) public {
    // ❌ 沒有驗證 msg.sender
    // 任何人都可以對已 approve 的 NFT 執行操作
}
```

**攻擊**：
1. 用戶在 TX1 呼叫 `NPM.approve(V3Utils, tokenId)`
2. 攻擊者在 TX2 前搶跑
3. 呼叫 `execute()` 提取所有流動性到自己地址

---

### H-05: TWAP 負數 Tick 計算錯誤

**問題**：當 `tickCumulativesDelta` 為負數時，需要向下取整，但合約沒有處理。

```solidity
// ❌ 錯誤
int24 tick = int24((tickCumulatives[0] - tickCumulatives[1]) / int56(uint56(twapSeconds)));

// ✅ 正確（Uniswap 官方實現）
int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
int24 tick = int24(tickCumulativesDelta / secondsAgo);
if (tickCumulativesDelta < 0 && (tickCumulativesDelta % secondsAgo != 0)) tick--;
```

**影響**：價格計算錯誤 → 清算判斷錯誤

---

### H-06: 惡意 onERC721Received 阻止清算

**問題**：清算時呼叫 `safeTransferFrom` 將 NFT 返還用戶，用戶可以拒絕接收。

```solidity
function _cleanupLoan(...) internal {
    // 在清算流程中被呼叫
    nonfungiblePositionManager.safeTransferFrom(address(this), owner, tokenId);
    // ↑ 如果 owner 是合約且 onERC721Received 返回錯誤值，這裡會 revert
}
```

**攻擊**：
```solidity
function onERC721Received(...) external returns (bytes4) {
    if (from == vault) return bytes4(0xdeadbeef);  // 拒絕接收
    return msg.sig;
}
```

**影響**：無法清算 → 壞帳累積 → 協議破產

---

## Lending Protocol Invariants

### 1. 利息計算
```
debt_at_time_t = debt_at_time_0 * debtExchangeRate(t)
interest_accrued > 0 when time_elapsed > 0
```

### 2. 清算可行性
```
∀ unhealthy_position:
  liquidation_tx MUST NOT revert
  liquidator_profit > gas_cost (incentive)
```

### 3. 抵押品限制
```
∀ token:
  totalDebtShares[token] <= collateralLimit[token]
  NOT bypassable via deposit-borrow-withdraw
```

### 4. Oracle 安全
```
price = f(chainlink_price, twap_price)
|chainlink - twap| < MAX_DEVIATION
```

### 5. 權限隔離
```
user can only operate on:
  - positions they own
  - positions explicitly approved to them
```

---

## 學到的教訓

1. **Permit2 需要完整驗證** - token 地址、金額、deadline 都要查
2. **ERC721 callback 是重入向量** - safeTransferFrom 前要完成所有狀態更新
3. **Calldata 中的參數也要驗證** - 不只是函數參數
4. **清算不能依賴用戶配合** - 用 pull 模式而非 push
5. **TWAP 數學要仔細** - 負數取整要特別處理
6. **同區塊借還是免費的** - 需要借款費用或最小借款時間

---

## 相關漏洞模式

- `vulnerability-patterns/access-control/missing-caller-validation.md`
- `vulnerability-patterns/reentrancy/erc721-callback.md`
- `vulnerability-patterns/input-validation/permit2-token.md`
