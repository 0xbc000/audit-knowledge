# THORChain - Code4rena June 2024

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Code4rena |
| **獎金池** | $36,500 USDC |
| **審計時間** | 2024-06-05 ~ 2024-06-12 |
| **協議類型** | Multi-chain DEX/Bridge |
| **原始碼** | [GitHub](https://github.com/code-423n4/2024-06-thorchain) |
| **報告** | [C4 Report](https://code4rena.com/reports/2024-06-thorchain) |
| **程式碼行數** | 1,517 nSLOC (Solidity + Go) |

## 協議概述

THORChain 是最大的跨鏈 DEX 之一，支援：
- Bitcoin
- Ethereum
- Cosmos
- 日交易量 $100M+

### 核心元件

1. **THORChain_Router** - EVM 鏈上的路由合約
2. **Vault System** - 管理跨鏈資產
3. **Allowance Mechanism** - 追蹤用戶和 vault 的授權額度

## 漏洞摘要

| ID | 嚴重度 | 標題 | 類型 |
|----|--------|------|------|
| H-01 | High | Rebasing Token (AMPL) 可盜取資金 | 代幣兼容性 |
| H-02 | High | transferOut 缺少授權檢查 | 權限控制 |
| M-01 | Medium | Fee-on-transfer 代幣 DoS | 代幣兼容性 |
| M-02 | Medium | ETH/WETH 回退處理不當 | 回退邏輯 |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 | high | code-confirmed | ✅ |
| H-02 | high | code-confirmed | ✅ |
| M-01 | medium | logic-inference | ❌ |
| M-02 | medium | logic-inference | ❌ |

---

## High Risk 詳細分析

### H-01: Rebasing Token 盜取資金 ⭐

**問題**：AMPL 等 rebasing token 在白名單中，但合約沒有處理 rebase 邏輯。

**AMPL 機制**：
- `_gonsPerFragment` 變數會改變所有餘額
- 目標是維持穩定價格（通過調整供應量）

**攻擊流程**：
```
1. 攻擊者存入 1000 AMPL（_gonsPerFragment = 1）
   - 合約餘額：1000
   - 攻擊者 allowance：1000

2. 執行 rebase(_gonsPerFragment = 2)
   - 合約餘額變成：500（因為 rebase）
   - 但 allowance 還是：1000 ❌

3. 攻擊者呼叫 transferAllowance 到惡意 router
   - 惡意 router 獲得 1000 token 授權

4. 受害者存入 1000 AMPL
   - 合約餘額：1500

5. 惡意 router 呼叫 transferFrom 提取 1000 token
   - 受害者的資金被盜
```

**PoC**：
```solidity
contract MaliciousRouter {
    function depositWithExpiry(...) public {}  // 空函數
    
    function steal(uint256 amount, address from, address to, address target) public {
        target.call(abi.encodeWithSignature(
            "transferFrom(address,address,uint256)", 
            from, to, amount
        ));
    }
}
```

**根本原因**：
- `_vaultAllowance` 記錄的是存款時的 token 數量
- 但 rebasing token 的實際餘額會變化
- approve 金額與實際餘額不同步

---

### H-02: transferOut 缺少授權檢查

**問題**：`transferOut` 函數沒有驗證 vault 是否有足夠授權。

```solidity
function transferOut(
    address payable to,
    address asset,
    uint amount,
    string memory memo
) public payable {
    // ❌ 沒有檢查 _vaultAllowance[msg.sender][asset]
    
    if (asset == address(0)) {
        to.call{value: msg.value}("");
    } else {
        _routerDeposit(router, vault, asset, amount, memo);
    }
}
```

**影響**：任何人可以呼叫 transferOut 消耗合約餘額。

---

## Medium Risk 詳細分析

### M-01: Fee-on-Transfer Token DoS

**問題**：存款時記錄的金額是 `amount`，但實際收到的是 `amount - fee`。

```solidity
function depositWithExpiry(...) public {
    safeTransferFrom(asset, msg.sender, address(this), amount);
    _vaultAllowance[vault][asset] += amount;  // ❌ 應該用實際收到的金額
}
```

**影響**：allowance 會比實際餘額高，導致後續操作失敗。

---

## Token 兼容性檢查清單

### Rebasing Tokens (AMPL, stETH, etc.)
- [ ] 餘額會在沒有交易的情況下變化
- [ ] 必須用「份額」而非「金額」追蹤
- [ ] 或者在每次操作時重新計算

### Fee-on-Transfer Tokens
- [ ] 轉帳後餘額差 ≠ 轉帳金額
- [ ] 使用 `balanceAfter - balanceBefore` 計算實際收到
- [ ] 不要直接用 `amount` 參數

### Approval Race Condition Tokens (USDT)
- [ ] 必須先 approve(0) 再 approve(newAmount)
- [ ] 或使用 safeIncreaseAllowance

### Non-Standard Return Tokens
- [ ] 不返回 bool 的 transfer/approve
- [ ] 使用 SafeERC20

---

## Bridge/Router Invariants

### 1. 授權追蹤
```
∀ vault, asset:
  _vaultAllowance[vault][asset] <= 
    actualBalance(asset) attributable to vault
```

### 2. Rebasing 安全
```
if (asset.isRebasing):
  track shares, not amounts
  OR recalculate on every operation
```

### 3. 操作原子性
```
deposit + allowance_update = atomic
withdraw + allowance_update = atomic
```

### 4. Router 信任
```
只有 trusted routers 可以：
- 獲得 token approval
- 執行 transferFrom
```

---

## 學到的教訓

1. **白名單 ≠ 安全** - AMPL 在白名單但仍有漏洞
2. **Rebasing 是特殊的** - 需要完全不同的會計邏輯
3. **Allowance vs Balance** - 兩者必須同步
4. **Router 權限** - 誰能成為 router、獲得什麼權限

---

## 相關漏洞模式

- `vulnerability-patterns/token/rebasing-token.md`
- `vulnerability-patterns/token/fee-on-transfer.md`
- `vulnerability-patterns/access-control/missing-auth.md`
