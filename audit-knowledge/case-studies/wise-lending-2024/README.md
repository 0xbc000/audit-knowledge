# Wise Lending - Code4rena February 2024

## 基本資訊

| 項目 | 內容 |
|------|------|
| **平台** | Code4rena |
| **獎金池** | ~$60,000 USDC |
| **審計時間** | 2024-02-21 ~ 2024-03-11 |
| **協議類型** | Lending Protocol |
| **原始碼** | [GitHub](https://github.com/code-423n4/2024-02-wise-lending) |
| **報告** | [C4 Report](https://code4rena.com/reports/2024-02-wise-lending) |
| **程式碼行數** | 44 contracts, 6,326 nSLOC |

## 協議概述

Wise Lending 是一個借貸協議，特色功能：
- 支援多種抵押品
- Bad Debt 機制 + 清償激勵
- 自定義重入保護機制

### 核心元件
- **WiseLending** - 主要借貸邏輯
- **FeeManager** - 費用管理 + Bad Debt 處理
- **WiseSecurity** - 安全檢查
- **PoolManager** - 資金池管理

## 漏洞摘要

| ID | 嚴重度 | 標題 | 類型 |
|----|--------|------|------|
| H-01 | High | receive() 函數重置重入保護 | 重入 |
| H-02 | High | 用戶可免費消除債務 | 邏輯錯誤 |
| H-03 | High | Oracle 價格操縱 | Oracle |
| H-04 | High | 清算獎勵計算錯誤 | 數學錯誤 |
| H-05 | High | 惡意 token 回調攻擊 | 重入 |
| M-01 ~ M-17 | Medium | 各種中等問題 | 多種 |

---

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 | high | code-confirmed | ✅ |
| H-02 | high | code-confirmed | ✅ |
| H-03 | medium | logic-inference | ❌ |
| H-04 | medium | logic-inference | ❌ |
| H-05 | medium | logic-inference | ❌ |

---

## High Risk 詳細分析

### H-01: receive() 函數重置重入保護 ⭐⭐

**問題**：自定義重入保護使用 `sendingProgress` 變數，但 `receive()` 函數會重置它。

```solidity
// _sendValue 中設定重入保護
function _sendValue(address _recipient, uint256 _amount) internal {
    sendingProgress = true;
    payable(_recipient).call{value: _amount}("");
    sendingProgress = false;  // ← 完成後重置
}

// receive() 也會呼叫 _sendValue
receive() external payable {
    if (msg.sender != WETH_ADDRESS) {
        _sendValue(master, msg.value);  // ← 這會重置 sendingProgress!
    }
}
```

**攻擊流程**：
1. 攻擊者呼叫 `withdrawExactAmountETH()` 提款
2. 收到 ETH 時重入
3. 發送 0.01 ETH 給 WiseLending 合約
4. `receive()` 觸發 → `sendingProgress` 被重置
5. 現在可以重入任何被保護的函數
6. 呼叫 `paybackBadDebtForToken()` 把自己的債務標記為壞帳
7. 清償壞帳獲得 5% 獎勵
8. 健康檢查通過（因為債務已清零）

**影響**：盜取協議資金

---

### H-02: 用戶可免費消除債務

**問題**：`_removePositionData()` 假設傳入的 `_poolToken` 一定存在於用戶陣列中，但沒有驗證。

```solidity
function _removePositionData(...) private {
    uint256 length = _getPositionTokenLength(_nftId);
    
    if (length == 1) {
        // ❌ 不管 _poolToken 是什麼都刪除
        _deleteLastPositionData(_nftId, _poolToken);
        return;
    }
    // ...
}
```

**攻擊**：
1. 借款產生少量 badDebt
2. 呼叫 `paybackBadDebtNoReward(nftId, USDC, 0)`
3. USDC 不在用戶的借款 token 列表中
4. 但最後一個 token（實際借款 token）被刪除
5. 債務記錄消失，用戶免費脫身

---

### H-03: Oracle 價格操縱

**問題**：TWAP 設置不當或 Chainlink 價格未充分驗證。

**風險點**：
- TWAP 時間窗口太短
- Chainlink 價格過期未檢查
- 多 hop 價格精度損失

---

## 重入保護設計教訓

### 錯誤模式
```solidity
// ❌ 可被重置的狀態變數
bool sendingProgress;

function protected() {
    require(!sendingProgress);
    sendingProgress = true;
    // ...
    sendingProgress = false;
}
```

### 正確模式
```solidity
// ✅ OpenZeppelin ReentrancyGuard
uint256 private _status = 1;
uint256 private constant _ENTERED = 2;

modifier nonReentrant() {
    require(_status != _ENTERED);
    _status = _ENTERED;
    _;
    _status = 1;
}
```

### 為什麼 OpenZeppelin 方式更安全
1. 使用 `uint256` 而非 `bool`（gas 優化）
2. 使用 `1` 和 `2` 而非 `true/false`
3. **不會被其他函數意外重置**

---

## Bad Debt 機制注意事項

1. **誰可以標記 bad debt** - 需要權限控制
2. **清償激勵是否被濫用** - 不能自己標記自己清償
3. **陣列操作的邊界檢查** - 刪除元素時要驗證存在性

---

## Lending Protocol Checklist

### 重入
- [ ] 所有外部呼叫前狀態是否已更新
- [ ] 重入保護機制是否可被繞過
- [ ] ERC20/721/1155 的 callback 是否處理

### Oracle
- [ ] 價格過期檢查
- [ ] 多來源價格驗證
- [ ] 精度處理

### 清算
- [ ] 健康因子計算正確性
- [ ] 清算激勵是否足夠
- [ ] 清算是否可被阻止

### Bad Debt
- [ ] 誰可以標記 bad debt
- [ ] 清償流程是否有漏洞
- [ ] 陣列/映射操作的邊界檢查

---

## 相關漏洞模式

- `vulnerability-patterns/reentrancy/custom-guard-bypass.md`
- `vulnerability-patterns/data-structure/array-deletion.md`
- `vulnerability-patterns/lending/bad-debt-manipulation.md`
