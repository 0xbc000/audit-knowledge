# EigenLayer Withdrawal Vulnerability (2024)

> **類型**: Staking / Restaking
> **來源**: Trail of Bits Audit (2024-01), Sigma Prime Review
> **獎金**: N/A (private audit)

## 概述

EigenLayer 是 Ethereum 上最大的 restaking 協議。多次安全審計中發現了 withdrawal delay 繞過與 slashing propagation 相關的漏洞。

## 關鍵發現

### H-01: Withdrawal Delay Bypass via Operator Change

**根因**: `withdrawal-delay:operator-change-bypass`

**描述**: 用戶可以透過先 undelegate、再 delegate 到新 operator，繞過原始的 withdrawal delay。因為 delay 是記錄在 delegation 關係上，而非 withdrawal request 上。

**Exploit Path**:
```
1. User delegates 100 ETH to Operator A (withdrawal delay = 7 days)
2. User calls undelegate() → creates withdrawal request
3. Before 7 days, user calls delegateTo(Operator B)
4. User immediately calls completeQueuedWithdrawal()
5. System checks: current delegation has no pending delay → allows withdrawal
6. Result: bypassed 7-day delay
```

**前置條件**:
- Withdrawal delay 綁在 operator delegation，而非 withdrawal request 本身
- 無 cooldown 阻止重複 delegate/undelegate

**修復**: Withdrawal request 記錄 `startBlock`，completion 檢查 `block.number >= startBlock + withdrawalDelayBlocks`，與當前 delegation 無關。

### M-01: Slashing Propagation Precision Loss

**根因**: `math:slashing-propagation-precision`

**描述**: 當 operator 被 slash 時，delegator shares 按比例減少。但整數除法的精度損失在大量 delegator 時累積，導致 vault 中實際資產 > 所有 delegator shares 的總價值。差額變成「無主資產」。

**可檢測規則**:
```solidity
// Invariant: total shares value should equal total assets (within dust)
assert(
  abs(totalAssets - sumSharesValue) <= delegatorCount * 1
);
```

## 可檢測規則摘要

| ID | 規則 | Pattern Key |
|----|------|-------------|
| R-01 | Withdrawal delay must be tied to request, not delegation | `withdrawal-delay:binding-point` |
| R-02 | Slashing propagation precision loss bounded by delegator count | `math:slashing-propagation-precision` |
| R-03 | Operator change should not reset withdrawal timers | `state-update:timer-reset-on-relink` |

## 學習重點

1. Restaking 中 withdrawal delay 的 binding point 是核心安全屬性
2. 大規模整數除法累積精度損失是 restaking 特有問題
3. Operator 切換是高風險操作，需要 cooldown

## 參考

- Trail of Bits: EigenLayer Security Assessment (2024-01)
- [EigenLayer Docs: Withdrawal Flow](https://docs.eigenlayer.xyz/)

## 標籤

`staking` `restaking` `withdrawal-delay` `slashing` `eigenlayer`
