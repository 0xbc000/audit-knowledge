# ERC-4337 Account Abstraction Vulnerabilities (2024)

> **類型**: Account Abstraction (ERC-4337)
> **來源**: Infinitism/account-abstraction audits, Alchemy Rundler analysis, Spearbit reviews
> **獎金**: Various bug bounties

## 概述

ERC-4337 生態系統中的 Paymaster、Smart Account、Bundler 元件均有特定攻擊面。以下彙整多次審計中反覆出現的漏洞模式。

## 關鍵發現

### H-01: Paymaster Drain via Gas Griefing

**根因**: `paymaster:deposit-drain`

**描述**: Verifying Paymaster 在 `validatePaymasterUserOp` 中同意 sponsor 一筆 UserOp 後，攻擊者的 UserOp 在 execution phase 執行大量 storage operations 消耗最大 gas。Paymaster 的 EntryPoint deposit 被快速耗盡，合法用戶無法再使用。

**Exploit Path**:
```
1. Paymaster validates UserOp: 預估 gas cost = 100K gas
2. UserOp execution: 用 SSTORE 填滿 gas limit (= verificationGasLimit + callGasLimit)
3. Actual gas consumed >> estimated → Paymaster 被收取最大 gas 費用
4. 重複 N 次 → Paymaster deposit 歸零
5. 所有依賴此 Paymaster 的用戶無法操作
```

**前置條件**:
- Paymaster 未設 per-user rate limit
- Paymaster 的 validatePaymasterUserOp 不檢查 callGasLimit 上限
- 攻擊者有能力提交 UserOps（通常是 permissionless）

**修復**:
```solidity
function validatePaymasterUserOp(UserOperation calldata userOp, ...) external returns (...) {
    // Rate limit per sender
    require(userOpCount[userOp.sender] < MAX_OPS_PER_PERIOD, "Rate limited");
    // Cap gas
    require(userOp.callGasLimit <= MAX_CALL_GAS, "Gas too high");
    userOpCount[userOp.sender]++;
    ...
}
```

### M-01: Cross-Chain UserOp Replay

**根因**: `signature:userOp-cross-chain-replay`

**描述**: Smart account 使用 CREATE2 在多鏈部署到相同地址。UserOp signature 中的 `chainId` 來自 account 的 `validateUserOp` 實現。若 account 實現有 bug（未將 chainId 納入 hash），同一 UserOp 可在另一條鏈重放。

**可檢測規則**:
```solidity
// validateUserOp must include chainId in signature verification
bytes32 hash = keccak256(abi.encode(
    userOp.hash(),
    address(this),  // account address
    block.chainid   // ← MUST be included
));
```

### M-02: initCode Front-Running

**根因**: `frontrun:account-creation`

**描述**: UserOp 含 `initCode` 時，bundler 提交交易前 mempool 中可見。攻擊者搶先用同一 initCode 部署 account，但指定自己為 owner。

**可檢測規則**: Factory 的 `createAccount` 應使用 sender address 作為 salt 的一部分，確保部署地址與 sender 綁定。

## 可檢測規則摘要

| ID | 規則 | Pattern Key |
|----|------|-------------|
| R-01 | Paymaster must rate-limit UserOps per sender | `paymaster:rate-limit` |
| R-02 | Paymaster should cap callGasLimit | `paymaster:gas-cap` |
| R-03 | validateUserOp must include chainId in signature hash | `signature:chainid-in-hash` |
| R-04 | Account factory must bind deploy address to owner | `frontrun:create2-salt-binding` |

## 學習重點

1. Paymaster 是 ERC-4337 最大攻擊面 — 它替別人付錢
2. Cross-chain replay 在 CREATE2 same-address 場景下是系統性風險
3. initCode visibility 在 public mempool 中是 front-running vector

## 參考

- ERC-4337 Specification: [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337)
- Infinitism EntryPoint Audits (OpenZeppelin, Spearbit)

## 標籤

`account-abstraction` `erc4337` `paymaster` `cross-chain-replay` `bundler`
