# Cross-Chain Bridge Invariants

## 核心 Invariants

### 1. 跨鏈總量守恆

```
源鏈鎖定量 = 目標鏈鑄造量
∀ asset: locked[source] == minted[destination]
```

任何時刻，鎖定和鑄造的代幣總量必須相等。

### 2. 訊息唯一性

```
每個跨鏈訊息只能執行一次
∀ messageId: executed[messageId] ∈ {0, 1}
```

防止重放攻擊。

### 3. 權限隔離

```
只有授權的 bridge/router 可以：
- 鑄造/銷毀 wrapped tokens
- 釋放鎖定資產
- 執行 callback
```

### 4. Gas 安全下界

```
destination_gas >= chain_specific_minimum
Arbitrum: >= 2M
其他 EVM: >= 200K
```

### 5. 地址有效性

```
∀ address in payload:
  address is valid on destination chain
  refund_address = user_controlled_address
```

### 6. 回退安全

```
if (execution_fails):
  funds → user_address
  NOT → random_contract
  NOT → stuck_forever
```

### 7. Channel 存活

```
single_message_failure ≠ channel_blocked
∀ failed_message: can be retried or refunded
```

---

## LayerZero 特定

### OFT (Omnichain Fungible Token)

```solidity
// 核心函數
sendFrom(from, dstChainId, toAddress, amount, ...);
// 源鏈銷毀/鎖定，目標鏈鑄造/釋放
```

### 訊息狀態

| 狀態 | 說明 |
|------|------|
| INFLIGHT | 傳輸中 |
| SUCCESS | 執行成功 |
| STORED | 執行失敗，已緩存 |

⚠️ `STORED` 狀態會阻塞同源同目標的後續訊息！

### Gas 配置

```solidity
// AdapterParams v1
abi.encodePacked(uint16(1), uint256(gasLimit))

// AdapterParams v2 (with airdrop)
abi.encodePacked(uint16(2), uint256(gasLimit), uint256(amount), address(to))
```

---

## Stargate 特定

### Composer 模式

```solidity
// 1. 轉移 token 到目標合約
// 2. 呼叫 sgReceive()
// 3. 如果 revert → 緩存 payload
```

### 注意事項

1. `sgReceive` revert 不會回滾 token 轉移
2. 緩存的 payload 可用 `clearCachedSwap` 重試
3. 如果參數過時（如 slippage），重試也會失敗

---

## 審計重點

### 權限控制
- [ ] mint/burn 函數的權限
- [ ] setRouter/setBridge 的權限
- [ ] 跨鏈 callback 的來源驗證

### Gas 處理
- [ ] 用戶能否控制 gas？
- [ ] 有沒有最低 gas 要求？
- [ ] 不同鏈的 gas 配置

### 地址編碼
- [ ] payload 中的地址在哪條鏈？
- [ ] refund 地址是否正確？
- [ ] 合約部署方式 (CREATE vs CREATE2)

### 回退邏輯
- [ ] 執行失敗時資金去向
- [ ] 餘額不足時的處理
- [ ] 緩存/重試機制

### Token 兼容
- [ ] Fee-on-transfer
- [ ] Rebasing tokens
- [ ] Non-standard ERC20
