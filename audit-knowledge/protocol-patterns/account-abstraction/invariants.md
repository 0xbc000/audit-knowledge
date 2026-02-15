# Account Abstraction (ERC-4337) Invariants

> 涵蓋 ERC-4337 UserOperation、Paymaster、Bundler 相關協議

## 核心不變量

1. **UserOp 驗證**: `account.validateUserOp()` 成功 ⟹ account 授權此操作
2. **Gas 預付**: `missingAccountFunds` 必須在 validateUserOp 時支付給 EntryPoint
3. **Paymaster 償付能力**: `paymaster.deposit ≥ sum(sponsored gas costs)` 在任何時刻
4. **Nonce 序列性**: `nonce = key || seq`，同一 key 下 seq 嚴格遞增
5. **Execution 隔離**: validateUserOp 的 storage access 限制必須被強制執行
6. **Bundler 補償**: `actualGasCost ≤ prefund` — bundler 不會虧損

## 高風險區域

### Paymaster Drain
- 惡意 UserOp 利用 paymaster 支付大量 gas 但不做有用操作
- `postOp` 回調中的狀態操控
- Paymaster 的 `validatePaymasterUserOp` 驗證不足
- 重複使用同一 paymaster approval signature

### Bundler Manipulation
- UserOp 在 simulation 時成功但執行時 revert（griefing bundler）
- `validateUserOp` 中使用禁止的 opcode 繞過 simulation
- Bundler 重排 UserOps 進行 MEV 提取
- Gas 估算不準導致 bundler 虧損

### Signature Replay Across Chains
- ERC-4337 account 在多鏈部署同一地址
- UserOp signature 缺少 chainId 驗證
- EntryPoint 地址相同導致跨鏈重放

### Account Recovery / Social Recovery
- Recovery 機制的時間鎖是否可被繞過
- Guardian collusion
- Recovery 期間的 operation 限制

## 特有攻擊向量

### Paymaster Drain Attack
```
1. 攻擊者創建大量 UserOps，paymaster 同意 sponsor
2. UserOps 消耗最大 gas（計算密集 + storage 操作）
3. 但對攻擊者無成本（paymaster 支付）
4. Paymaster deposit 被快速耗盡
```
**防禦**: Rate limiting、per-user cap、off-chain validation

### Cross-Chain Signature Replay
```
1. User 在 Chain A 簽署 UserOp (nonce=0)
2. 攻擊者在 Chain B deploy 相同 account (CREATE2 same address)
3. Replay 同一 UserOp signature on Chain B
4. Nonce 也是 0，EntryPoint 地址相同 → 執行成功
```
**防禦**: Signature 必須包含 chainId、或使用 EIP-712 domain separator

### Bundler Griefing
```
1. UserOp simulation: validateUserOp succeeds
2. Between simulation and inclusion: account state changes
3. On-chain: validateUserOp reverts
4. Bundler pays gas but gets no compensation
```
**防禦**: ERC-4337 storage access rules、reputation system

### postOp Manipulation
```
1. Paymaster 在 postOp 中嘗試 charge user
2. User 在 execution phase 修改狀態使 postOp 失敗
3. postOp(mode=opReverted) 仍被調用
4. Paymaster 需要處理所有 failure modes
```
**防禦**: postOp 必須能處理任何狀態

## 相關漏洞模式

```
vulnerability-patterns/access-control/* — account 權限驗證
vulnerability-patterns/reentrancy/* — execution 與 validation 的分離
vulnerability-patterns/math/* — gas 計算
vulnerability-patterns/cross-chain/* — 多鏈 account 重放
vulnerability-patterns/upgrade/* — account 升級安全性
```

## 審計 Checklist

| # | 檢查項目 | 嚴重性 |
|---|---------|--------|
| 1 | Signature 是否包含 chainId？ | Critical |
| 2 | Paymaster deposit 是否有 drain 保護？ | Critical |
| 3 | validateUserOp 是否遵守 storage rules？ | High |
| 4 | Nonce 管理是否正確？ | High |
| 5 | postOp 是否能處理所有 failure modes？ | High |
| 6 | Account 初始化是否有 front-running 保護？ | High |
| 7 | Gas overhead 計算是否準確？ | Medium |
