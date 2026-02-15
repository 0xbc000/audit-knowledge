# Staking / Restaking Protocol Invariants

> 涵蓋 EigenLayer 類型的 restaking 協議

## 核心不變量

1. **Shares ↔ Assets 一致性**: `sum(operator.delegatedShares[strategy]) ≤ strategy.totalShares`
2. **Withdrawal 完整性**: 用戶排隊的 withdrawal 在延遲期後必須可執行，且金額正確
3. **Slashing 傳播正確性**: `slashedAmount(operator) = sum(slashedAmount(delegator_i))` 按比例分配
4. **雙重質押禁止**: 同一資產不能同時被兩個 operator 使用（除非協議明確允許）
5. **Delegation 守恆**: `sum(delegator.shares) == operator.totalDelegatedShares`
6. **Withdrawal delay 不可跳過**: `block.timestamp >= queuedWithdrawal.completableTimestamp` 才能 complete
7. **Operator 註冊唯一性**: 一個地址不能同時是 operator 和 delegator 給另一個 operator

## 高風險區域

### Slashing Propagation
- Slashing 跨 strategy 傳播時的精度損失
- 部分 slashing 後 share 價值重算
- Slashing 期間的 withdrawal race condition

### Withdrawal Delay
- Delay 參數可否被 operator 或 governance 操控
- 排隊中的 withdrawal 是否受後續 slashing 影響
- 批量 withdrawal 的 gas 限制

### Operator Management
- Operator 註冊/退出的時間鎖
- 惡意 operator 的 collusion 攻擊
- Operator metadata 修改的時機

### Reward Distribution
- Restaking 獎勵的正確歸屬
- 跨多個 AVS 的獎勵聚合
- Reward 與 slashing 的交互

## 特有攻擊向量

### Slashing Propagation Attack
```
1. Operator 接受大量委託
2. 故意觸發 slashing 條件
3. 在 slashing 執行前提取自己的 stake
4. 所有 slashing 由 delegator 承擔
```
**防禦**: Operator 退出延遲 > slashing 檢測窗口

### Withdrawal Delay Manipulation
```
1. Governance 提案降低 withdrawal delay
2. 在提案通過前排隊大量 withdrawal
3. 提案通過後立即 complete（跳過原始延遲）
```
**防禦**: Withdrawal 記錄建立時的 delay 參數

### Operator Collusion
```
1. 多個 operator 共謀
2. 同時觸發 slashing + withdrawal
3. 利用系統處理順序獲利
```
**防禦**: 全局 slashing 優先於 withdrawal 執行

## 相關漏洞模式

```
vulnerability-patterns/math/* — share 計算精度
vulnerability-patterns/access-control/* — operator 權限
vulnerability-patterns/reentrancy/* — withdrawal callback
vulnerability-patterns/business-logic/* — slashing 邏輯
```

## 審計 Checklist

| # | 檢查項目 | 嚴重性 |
|---|---------|--------|
| 1 | Slashing 是否正確按比例傳播？ | Critical |
| 2 | Withdrawal 延遲是否不可繞過？ | Critical |
| 3 | Operator 退出是否有足夠延遲？ | High |
| 4 | Share 計算是否有精度損失？ | High |
| 5 | 獎勵分配是否可被搶先？ | Medium |
| 6 | 跨 AVS 的 slashing 是否獨立？ | High |
