# Decent Bridge - Code4rena January 2024

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Code4rena |
| **獎金池** | $36,500 USDC |
| **審計時間** | 2024-01-19 ~ 2024-01-23 |
| **協議類型** | Cross-Chain Bridge (LayerZero) |
| **原始碼** | [GitHub](https://github.com/code-423n4/2024-01-decent) |
| **報告** | [C4 Report](https://code4rena.com/reports/2024-01-decent) |
| **程式碼行數** | 1,209 nSLOC |

## 協議概述

Decent 允許用戶在任何鏈上用任何 token 完成單擊交易。
例如：用 Base 上的 DAI 支付，購買 Optimism 上的 NFT。

### 核心架構

1. **UTB (Universal Transaction Builder)** - 路由跨鏈交易，調用 swapper 和 bridge adapter
2. **DecentBridge** - 基於 LayerZero OFT 標準的自定義橋
3. **DecentEthRouter** - 橋的核心邏輯
4. **DcntEth** - LayerZero OFT 代幣
5. **DecentBridgeExecutor** - 目標鏈上執行交易
6. **StargateBridgeAdapter** - Stargate 橋接適配器

### 兩種模式
- **swapAndExecute** - 同鏈交易
- **bridgeAndExecute** - 跨鏈交易

## 漏洞摘要

| ID | 嚴重度 | 標題 | 類型 |
|----|--------|------|------|
| H-01 | High | DcntEth.setRouter() 無權限控制 | 權限控制 |
| H-02 | High | LayerZero gas 檢查缺失導致 channel 阻塞 | 跨鏈 Gas |
| H-03 | High | execute 失敗時 refund 發到錯誤地址 | 地址編碼 |
| H-04 | High | WETH 不足時 dcntEth 發到錯誤目標 | 回退邏輯 |
| M-01 | Medium | Stargate swap 失敗導致代幣永久鎖定 | 跨鏈回退 |
| M-02 | Medium | UTBExecutor 可被重入攻擊 | 重入 |
| M-03 | Medium | Stargate 手續費計算錯誤 | 費用計算 |
| M-04 | Medium | 跨鏈 refund 地址錯誤 | 地址編碼 |
| M-05 | Medium | receiveFromBridge 缺少來源驗證 | 權限控制 |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 | high | code-confirmed | ✅ |
| H-02 | medium | logic-inference | ❌ |
| H-03 | high | code-confirmed | ✅ |
| H-04 | high | code-confirmed | ✅ |
| M-01 | medium | logic-inference | ❌ |
| M-02 | medium | logic-inference | ❌ |
| M-03 | medium | logic-inference | ❌ |
| M-04 | medium | logic-inference | ❌ |
| M-05 | medium | code-confirmed | ❌ |

---

## High Risk 詳細分析

### H-01: setRouter() 無權限控制 ⭐

**問題**：任何人都可以呼叫 `DcntEth.setRouter()` 設定 router 地址。

```solidity
// ❌ 沒有 access control
function setRouter(address _router) public {
    router = _router;
}
```

**攻擊**：
1. 攻擊者呼叫 `setRouter(attacker_address)`
2. 攻擊者現在可以呼叫 `mint()` 和 `burn()`
3. 無限 mint DcntEth → 提走所有 WETH

**影響**：整個 TVL 被盜。

---

### H-02: LayerZero Gas 不足導致 Channel 阻塞

**問題**：`GAS_FOR_RELAY` 硬編碼為 100,000，用戶可傳入任意 `_dstGasForCall`。

```solidity
uint256 GAS_FOR_RELAY = 100000;  // 硬編碼
uint256 gasAmount = GAS_FOR_RELAY + _dstGasForCall;  // 用戶控制
```

**攻擊**：
1. 傳入極小的 `_dstGasForCall`
2. 目標鏈 out-of-gas
3. 訊息狀態變為 `STORED`
4. **阻塞整個跨鏈 channel**

**LayerZero 建議**：至少 200,000 gas（Arbitrum 需要 2M）。

---

### H-03: Refund 發到錯誤地址

**問題**：`_from` 被編碼為源鏈的 `DecentBridgeAdapter` 地址，但這個地址在目標鏈不存在。

```solidity
// 源鏈編碼
payload = abi.encode(msgType, msg.sender, _toAddress, deliverEth);
//                           ^^^^^^^^^^^ = DecentBridgeAdapter (源鏈)

// 目標鏈解碼
(uint8 msgType, address _from, ...) = abi.decode(_payload, ...);

// execute 失敗時
if (!success) {
    payable(from).transfer(amount);  // ❌ 錯誤地址
}
```

**影響**：execute 失敗時，資金發到隨機地址，永久丟失。

---

### H-04: WETH 不足時的錯誤回退

**問題**：當目標鏈 router 的 WETH 不足時，dcntEth 被發到 `_to` 地址，但 `_to` 是執行目標（通常是 bridge adapter），不是用戶。

```solidity
if (weth.balanceOf(address(this)) < _amount) {
    dcntEth.transfer(_to, _amount);  // ❌ _to 不是用戶
    return;
}
```

**影響**：用戶的 dcntEth 卡在 bridge adapter 合約，無法提取。

---

## Medium Risk 詳細分析

### M-01: Stargate Swap 失敗導致永久鎖定

**問題**：Stargate 的 `sgReceive` 如果 swap 失敗，會將 payload 緩存。但由於 swap 參數過時（如 minAmountOut），重試也會失敗。

**流程**：
1. Stargate 轉移代幣到 adapter
2. `sgReceive` 呼叫 swap，但 slippage 過時 → 失敗
3. Payload 被緩存，代幣留在 adapter
4. 重試用相同 payload → 永遠失敗

**修復**：用 try-catch 包裝，失敗時直接返還用戶。

---

### M-05: receiveFromBridge 缺少來源驗證

**問題**：`UTB.receiveFromBridge()` 沒有驗證呼叫者是否為註冊的 bridge adapter。

```solidity
function receiveFromBridge(...) public payable {
    // ❌ 沒有 onlyBridgeAdapter modifier
}
```

**影響**：任何人可以呼叫，可能導致意外行為。

---

## 跨鏈橋 Invariants

### 1. 權限控制
```
∀ privileged_function:
  caller ∈ authorized_set
```
- 關鍵函數必須有權限控制
- 特別是 mint/burn、setRouter 等

### 2. Gas 安全
```
destination_gas >= minimum_required_gas
minimum_required_gas >= LayerZero_recommendation
```
- 不能讓用戶控制 gas 到低於安全值
- 考慮不同鏈的 gas 需求（Arbitrum 更高）

### 3. 地址一致性
```
refund_address = user_address_on_destination_chain
NOT: source_chain_contract_address
```
- 跨鏈 payload 中的地址必須是目標鏈的有效地址
- 源鏈合約地址在目標鏈通常無效

### 4. 回退安全
```
if (normal_flow_fails):
  funds → user_controlled_address
  NOT: random_contract
```
- 任何失敗路徑都必須安全返還資金
- 不能依賴「目標合約會處理」

### 5. Channel 存活
```
cross_chain_message should NOT block channel
even if execution fails
```
- 單筆失敗不應阻塞後續訊息
- 需要適當的錯誤處理機制

---

## 學到的教訓

1. **權限控制是基礎** - H-01 是最基本的 access control 漏洞
2. **跨鏈地址編碼** - 源鏈地址 ≠ 目標鏈地址
3. **LayerZero Gas** - 必須強制最小值，不能讓用戶任意設定
4. **回退路徑** - 每個 else/catch 都要想清楚資金去向
5. **Stargate 特性** - sgReceive 失敗會緩存，需要特殊處理

---

## 相關協議類型

- `protocol-patterns/cross-chain-bridge/invariants.md`
