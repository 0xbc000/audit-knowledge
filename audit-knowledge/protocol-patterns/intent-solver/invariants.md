# Intent / Solver Protocol Invariants

> 涵蓋 UniswapX / CoW Protocol 類型的 intent-based 交易協議

## 核心不變量

1. **用戶保障**: `amountOut ≥ order.minAmountOut` — solver 必須滿足用戶最低預期
2. **Order 唯一性**: 每個 order (nonce) 只能被 fill 一次
3. **過期強制**: `block.timestamp ≤ order.deadline` — 過期訂單不可執行
4. **簽名有效性**: 只有 order signer 授權的訂單可被執行
5. **Solver 結算**: solver 必須在同一交易中完成 fill，不可欠債
6. **Dutch Auction 單調性**: 隨時間推移，用戶獲得的價格只能越來越好（或持平）

## 高風險區域

### Solver Collusion
- 多個 solver 共謀不競爭，讓用戶拿到最差價格
- Solver 與 builder 合作進行 order flow 拍賣
- 獨家 solver 模式的定價公平性

### Order Expiry
- 過期訂單的 signature 洩漏後能否被重放
- 時間戳依賴（`block.timestamp` 可被微調）
- 跨鏈 order 的時間同步

### Price Staleness
- Dutch auction 起始/結束價格設定不當
- 市場劇烈波動時的 MEV 提取
- Oracle 用於定價時的延遲

### Fill Validation
- 部分 fill 的正確性
- 多 token output 的驗證
- Fee-on-transfer token 與 fill amount 的差異

## 特有攻擊向量

### Solver Extraction
```
1. User 簽署 order: sell 1 ETH for ≥ 3000 USDC
2. Market price: 3500 USDC/ETH
3. Colluding solver fills at exactly 3000 USDC
4. Solver keeps 500 USDC spread
```
**防禦**: Dutch auction 機制、多 solver 競爭、鏈下拍賣

### Signature Replay Cross-Chain
```
1. User signs order on Chain A (no chainId in signature)
2. Same order replayed on Chain B
3. User loses funds on both chains
```
**防禦**: EIP-712 domain separator 包含 chainId

### Stale Dutch Auction
```
1. Order created with decayStart = now, decayEnd = now + 1h
2. Block inclusion delayed by builder (MEV)
3. Order executes at unfavorable point in decay curve
```
**防禦**: 用戶設定合理的 decay 範圍和最低限價

## 相關漏洞模式

```
vulnerability-patterns/access-control/* — solver 權限
vulnerability-patterns/oracle/* — 定價參考
vulnerability-patterns/math/* — Dutch auction 衰減計算
vulnerability-patterns/cross-chain/* — 跨鏈 order 重放
vulnerability-patterns/token/* — fee-on-transfer fill 差異
```

## 審計 Checklist

| # | 檢查項目 | 嚴重性 |
|---|---------|--------|
| 1 | Order nonce 是否防重放？ | Critical |
| 2 | 簽名是否包含 chainId？ | Critical |
| 3 | minAmountOut 是否嚴格執行？ | Critical |
| 4 | Dutch auction 衰減公式是否正確？ | High |
| 5 | 部分 fill 是否正確計算？ | High |
| 6 | 過期後簽名是否無效？ | High |
| 7 | Solver 是否可提取超額價值？ | Medium |
