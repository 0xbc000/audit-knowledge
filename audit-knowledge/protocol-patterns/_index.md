# Protocol Patterns Index

> 協議類型 → 不變量 + 相關漏洞模式 + 案例研究

## 協議類型識別指南

| 關鍵字 | 協議類型 | 核心功能 |
|--------|----------|----------|
| borrow, lend, collateral, liquidate | Lending | 抵押借貸 |
| swap, pool, liquidity, AMM | DEX/AMM | 代幣交換 |
| bridge, cross-chain, LayerZero, message | Bridge | 跨鏈 |
| perpetual, leverage, margin, funding | Perp DEX | 永續合約 |
| stake, reward, emission, epoch | Staking | 質押獎勵 |
| restake, AVS, operator, slashing | Restaking | 再質押 (EigenLayer) |
| intent, solver, order, fill, dutch | Intent/Solver | 意圖交易 (UniswapX) |
| userOp, paymaster, bundler, entrypoint | Account Abstraction | 帳戶抽象 (ERC-4337) |
| vault, deposit, withdraw, shares | ERC4626 Vault | 收益聚合 |
| NFT, rent, lease, collateral | NFT Lending | NFT 借貸 |
| vote, proposal, execute, timelock | Governance | 治理 |
| mint, burn, peg, rebase | Stablecoin | 穩定幣 |
| restake, AVS, operator, slash, EigenLayer | Staking/Restaking | 再質押 |
| intent, solver, order, fill, Dutch auction | Intent/Solver | 意圖交易 |
| userOp, bundler, paymaster, entryPoint, 4337 | Account Abstraction | 帳戶抽象 |

---

## Lending Protocol

**檔案:** [lending/invariants.md](lending/invariants.md)

**核心不變量:**
1. totalDeposits ≥ totalBorrows (always)
2. User cannot withdraw more than their balance
3. Liquidation only when position is unhealthy
4. Interest accrual must be monotonic
5. Collateral value > debt value for healthy positions

**高風險區域:**
- Oracle 價格獲取
- 利率計算（精度損失）
- 清算邏輯
- 閃電貸攻擊

**載入漏洞模式:**
```
vulnerability-patterns/oracle/*
vulnerability-patterns/math/*
vulnerability-patterns/erc4626/*
vulnerability-patterns/reentrancy/*
```

**相關案例:**
- revert-lend-2024 (6H, 27M)
- wise-lending-2024 (5H, 17M)
- size-2024 (4H, 13M)
- sentiment-v2-2024

---

## Cross-Chain Bridge

**檔案:** [cross-chain-bridge/invariants.md](cross-chain-bridge/invariants.md)

**核心不變量:**
1. sum(locked on source) = sum(minted on dest)
2. Message cannot be replayed
3. Only valid relayer can submit proofs
4. Refund goes to original sender
5. Gas provided must be sufficient for dest execution

**高風險區域:**
- 消息驗證
- 地址編碼（不同鏈格式）
- Gas 估算
- Refund 邏輯

**載入漏洞模式:**
```
vulnerability-patterns/cross-chain/*
vulnerability-patterns/access-control/*
vulnerability-patterns/upgrade/*
```

**相關案例:**
- decent-2024 (4H, 5M)
- thorchain-2024 (2H, 2M)

---

## Perp DEX

**檔案:** [perp-dex/invariants.md](perp-dex/invariants.md)

**核心不變量:**
1. sum(long OI) should roughly equal sum(short OI)
2. Funding rate correctness
3. Liquidation price calculation
4. PnL settlement accuracy
5. Margin requirements

**高風險區域:**
- 價格 Oracle (TWAP 操縱)
- 資金費率計算
- 槓桿清算
- 權重分配

**載入漏洞模式:**
```
vulnerability-patterns/oracle/*
vulnerability-patterns/math/*
vulnerability-patterns/business-logic/*
```

**相關案例:**
- zaros-2025 (權重分配錯誤)

---

## NFT Lending

**檔案:** [nft-lending/invariants.md](nft-lending/invariants.md)

**核心不變量:**
1. NFT ownership transfers correctly on loan start
2. NFT returns to borrower on repayment
3. NFT goes to lender on default
4. Loan terms are immutable after creation
5. Interest calculation is correct

**高風險區域:**
- NFT 價格 Oracle
- 貸款條款驗證
- 違約處理
- ERC721 callback

**載入漏洞模式:**
```
vulnerability-patterns/oracle/*
vulnerability-patterns/reentrancy/*
vulnerability-patterns/access-control/*
```

**相關案例:**
- raac-2025 (Oracle staleness)

---

## ERC4626 Vault

**核心不變量:**
1. shares * totalAssets / totalSupply = user assets
2. deposit(x) then redeem(shares) returns ~x
3. preview functions match actual results
4. Rounding favors the vault

**高風險區域:**
- 第一存款者攻擊
- 取整方向
- Preview 函數一致性
- Donation 攻擊

**載入漏洞模式:**
```
vulnerability-patterns/erc4626/*
vulnerability-patterns/math/*
vulnerability-patterns/reentrancy/*
```

---

## Staking / Restaking

**檔案:** [staking-restaking/invariants.md](staking-restaking/invariants.md)

**核心不變量:**
1. Slashing 按比例傳播
2. Withdrawal delay 不可繞過
3. Operator 退出有時間鎖
4. Share ↔ asset 一致性
5. 跨 AVS slashing 獨立

**高風險區域:**
- Slashing propagation
- Withdrawal delay manipulation
- Operator collusion

**載入漏洞模式:**
```
vulnerability-patterns/math/*
vulnerability-patterns/access-control/*
vulnerability-patterns/business-logic/*
```

---

## Intent / Solver

**檔案:** [intent-solver/invariants.md](intent-solver/invariants.md)

**核心不變量:**
1. Order 只能 fill 一次
2. amountOut ≥ minAmountOut
3. 過期訂單不可執行
4. 簽名包含 chainId

**高風險區域:**
- Solver collusion
- Order expiry / signature replay
- Dutch auction 定價

**載入漏洞模式:**
```
vulnerability-patterns/access-control/*
vulnerability-patterns/oracle/*
vulnerability-patterns/cross-chain/*
```

---

## Account Abstraction (ERC-4337)

**檔案:** [account-abstraction/invariants.md](account-abstraction/invariants.md)

**核心不變量:**
1. UserOp 簽名正確驗證
2. Paymaster deposit 不被耗盡
3. Nonce 嚴格遞增
4. Bundler 不虧損

**高風險區域:**
- Paymaster drain
- Cross-chain signature replay
- Bundler griefing

**載入漏洞模式:**
```
vulnerability-patterns/access-control/*
vulnerability-patterns/cross-chain/*
vulnerability-patterns/math/*
```

---

## Staking (Legacy)

**核心不變量:**
1. sum(user stakes) = totalStaked
2. Rewards are proportional to stake and time
3. Unstake returns at least principal (unless slashing)
4. Reward rate is correctly applied

**高風險區域:**
- 獎勵計算精度
- 時間加權
- 第一質押者優勢

**載入漏洞模式:**
```
vulnerability-patterns/math/*
vulnerability-patterns/reentrancy/*
vulnerability-patterns/access-control/*
```

---

## Staking / Restaking (NEW)

**檔案:** [staking-restaking/invariants.md](staking-restaking/invariants.md)

**核心不變量:**
1. sum(user_shares) * exchange_rate = totalStaked
2. Withdrawal queue FIFO 不可被打亂
3. Slashing 只影響目標 operator 的 stakers
4. Cross-AVS exposure 正確計算
5. Withdrawal delay 不可繞過

**高風險區域:**
- Slashing propagation 計算
- Withdrawal delay bypass
- Operator collusion
- Share inflation attack

**載入漏洞模式:**
```
vulnerability-patterns/math/*
vulnerability-patterns/reentrancy/*
vulnerability-patterns/access-control/*
vulnerability-patterns/upgrade/*
```

---

## Intent / Solver (NEW)

**檔案:** [intent-solver/invariants.md](intent-solver/invariants.md)

**核心不變量:**
1. user output ≥ order.minOutput
2. 過期 order 不可執行
3. 同一 order 不可 replay
4. Exclusivity window 嚴格執行
5. Input token 只在正確填滿時轉移

**高風險區域:**
- Solver collusion
- Dutch auction decay 計算錯誤
- Cross-chain signature replay
- Partial fill accounting

**載入漏洞模式:**
```
vulnerability-patterns/signature/*
vulnerability-patterns/math/*
vulnerability-patterns/cross-chain/*
```

---

## Account Abstraction / ERC-4337 (NEW)

**檔案:** [account-abstraction/invariants.md](account-abstraction/invariants.md)

**核心不變量:**
1. UserOp.sender 必須是合法合約
2. Nonce 嚴格遞增（2D nonce）
3. Paymaster deposit ≥ pending ops 費用
4. EntryPoint balance accounting 一致
5. Signature 包含 chainId + entryPoint

**高風險區域:**
- Paymaster drain
- Bundler MEV manipulation
- Cross-chain UserOp replay
- initCode front-running

**載入漏洞模式:**
```
vulnerability-patterns/signature/*
vulnerability-patterns/access-control/*
vulnerability-patterns/reentrancy/*
```
