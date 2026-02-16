# UniswapX / Intent-Solver Vulnerabilities (2024)

> **類型**: Intent / Solver
> **來源**: OpenZeppelin Audit (2023-07), Bug Bounty Reports (2024)
> **獎金**: Immunefi bounties

## 概述

UniswapX 是 intent-based 交易協議，用戶簽署 order（intent），solver 競爭填單。審計與 bug bounty 中發現了多個與 order replay、Dutch auction 定價相關的漏洞。

## 關鍵發現

### H-01: Cross-Chain Order Replay

**根因**: `signature:cross-chain-replay`

**描述**: UniswapX 的 Exclusive Dutch Order 簽名在早期版本中未包含 `chainId` 在 order struct 內（僅在 EIP-712 domain separator 中）。但當 ExclusiveDutchOrderReactor 在多鏈部署到相同地址（CREATE2）時，domain separator 相同，導致 order 可跨鏈重放。

**Exploit Path**:
```
1. User signs order on Ethereum: sell 1 WETH for ≥ 3000 USDC
2. Order is filled on Ethereum normally
3. Attacker replays same signature on Arbitrum
   - Same reactor address (CREATE2)
   - Same domain separator
   - Nonce not shared cross-chain
4. User's WETH on Arbitrum is sold at potentially outdated price
```

**前置條件**:
- Reactor 在多鏈部署到相同地址
- 用戶在多鏈有 token approval 給 Permit2
- Nonce management 是 per-chain

**修復**: Order struct 內增加 `chainId` field，signature 包含明確的 chain binding。

### M-01: Exclusive Filler Front-Running Decay Start

**根因**: `business-logic:dutch-auction-timing`

**描述**: Dutch auction 的 `decayStartTime` 由 order signer 設定。如果 block inclusion 被延遲（MEV builder holding），order 在 decay curve 上的執行點偏移，exclusive filler 可獲得不公平的定價。

**可檢測規則**:
```solidity
// Check: decay should not have started significantly before inclusion
assert(block.timestamp - order.decayStartTime <= MAX_ACCEPTABLE_DELAY);
```

## 可檢測規則摘要

| ID | 規則 | Pattern Key |
|----|------|-------------|
| R-01 | Order signature must include chainId in struct (not just domain) | `signature:chain-binding` |
| R-02 | Nonce must be shared or coordinated cross-chain | `replay:cross-chain-nonce` |
| R-03 | Dutch auction execution timing should be validated | `business-logic:decay-timing` |
| R-04 | Exclusive filler period should not be exploitable for MEV | `mev:exclusive-filler` |

## 學習重點

1. EIP-712 domain separator 的 chainId 在 CREATE2 same-address 場景下不夠
2. Intent-based 交易的跨鏈安全需要 order-level chain binding
3. Dutch auction timing 與 block inclusion 的交互是 MEV 攻擊面

## 參考

- OpenZeppelin: UniswapX Security Audit (2023-07)
- [UniswapX Design](https://blog.uniswap.org/uniswapx-protocol)

## 標籤

`intent` `solver` `cross-chain-replay` `dutch-auction` `uniswapx`
