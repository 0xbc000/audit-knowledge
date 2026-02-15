# veToken 治理協議 - Invariants 與審計要點

## 協議類型描述

veToken（Vote-Escrowed Token）是 Curve Finance 開創的治理代幣模式，用戶鎖定代幣獲得：
1. **投票權** - 參與治理投票
2. **Boost** - 獎勵加成（最高 2.5x）
3. **收益分成** - 協議費用分配

## 核心參與者

| 角色 | 行為 | 風險 |
|------|------|------|
| Locker | 鎖定代幣獲得 veToken | 被鎖資金無法提取 |
| Voter | 投票決定 gauge 權重 | 投票權可能被稀釋 |
| Gauge | 分發獎勵 | 權重被操縱 |
| Delegatee | 接受委託的投票權 | 委託期間無法撤回 |

## 核心 Invariants

### 1. 投票權計算

```solidity
// 投票權應隨時間線性衰減
votingPower(t) = lockedAmount * (unlockTime - t) / MAX_LOCK_DURATION

// Invariant: 投票權永不超過鎖定量
assert(votingPower(user) <= lockedAmount)

// Invariant: 投票權隨時間單調遞減
assert(votingPower(t2) <= votingPower(t1)) // when t2 > t1

// Invariant: 解鎖時投票權為 0
assert(block.timestamp >= unlockTime => votingPower == 0)
```

### 2. 鎖定機制

```solidity
// Invariant: 只能增加鎖定量或延長時間，不能減少
assert(newAmount >= oldAmount)
assert(newUnlockTime >= oldUnlockTime)

// Invariant: 鎖定期限在有效範圍內
assert(unlockTime - block.timestamp >= MIN_LOCK_DURATION)
assert(unlockTime - block.timestamp <= MAX_LOCK_DURATION)

// Invariant: 總鎖定量等於所有用戶鎖定之和
assert(totalLocked == sum(locks[user].amount for all users))
```

### 3. Boost 計算

```solidity
// Curve 風格 boost 公式
// boost = min(userBalance, 0.4 * depositAmount + 0.6 * totalDeposits * userVe / totalVe)
//         / (0.4 * depositAmount) 

// Invariant: Boost 在 1x ~ 2.5x 之間
assert(boost >= MIN_BOOST) // 10000 = 1x
assert(boost <= MAX_BOOST) // 25000 = 2.5x

// Invariant: 無 veToken 時 boost = 1x
assert(veBalance == 0 => boost == MIN_BOOST)
```

### 4. Gauge 權重

```solidity
// Invariant: 所有 gauge 權重總和 = 100%
assert(sum(gaugeWeights) == WEIGHT_PRECISION)

// Invariant: 用戶投票權 <= 其 veToken 餘額
assert(userVotesUsed <= veBalanceOf(user))

// Invariant: 投票後需等待冷卻期
assert(block.timestamp >= lastVoteTime + VOTE_DELAY)
```

## 常見漏洞模式

### 1. 投票權計算錯誤

```solidity
// ❌ RAAC - VotingPowerLib.sol
// 正確的 Curve 風格計算被註釋
// bias = RAACVoting.calculateBias(amount, unlockTime, block.timestamp);

// 簡化版可能有精度問題
uint256 initialPower = (amount * duration) / MAX_LOCK_DURATION;
```

**檢查點**:
- [ ] slope 計算是否正確？
- [ ] bias 是否隨時間正確衰減？
- [ ] 跨越 checkpoint 時是否正確更新？

### 2. Boost 計算與文檔不符

```solidity
// ❌ 聲稱 "Curve-style boost" 但實際只是線性比例
function calculateBoost(...) returns (uint256) {
    // 實際上：
    uint256 votingPowerRatio = (veBalance * 1e18) / totalVeSupply;
    return minBoost + (votingPowerRatio * boostRange) / 1e18;
    // 這不是 Curve 公式！
}
```

**檢查點**:
- [ ] 對比 Curve 原始公式
- [ ] 測試極端情況（0 veToken, 100% veToken）

### 3. Emergency Withdraw 繞過鎖定

```solidity
// ❌ 沒有足夠的延遲或懲罰
function emergencyWithdraw() external {
    // 應該有：
    // 1. 時間鎖
    // 2. 懲罰（如損失部分代幣）
    // 3. 投票權歸零
}
```

**檢查點**:
- [ ] emergency 有足夠延遲？
- [ ] 是否有懲罰機制？
- [ ] 是否正確歸零投票權？

### 4. 委託攻擊

```solidity
// ❌ 委託期間投票權可能被重複計算
function delegate(address to) external {
    // 需確保：
    // 1. 原持有人不能再投票
    // 2. 受委託人正確獲得投票權
    // 3. 委託不能重複
}
```

## 審計 Checklist

### 鎖定機制
- [ ] 最小/最大鎖定期限檢查
- [ ] 鎖定量上限檢查
- [ ] 只能增加不能減少
- [ ] 解鎖時間正確計算

### 投票權
- [ ] 衰減曲線正確
- [ ] Checkpoint 機制正確
- [ ] 歷史查詢正確
- [ ] 總投票權正確追蹤

### Boost
- [ ] 公式與文檔一致
- [ ] 邊界值正確處理
- [ ] 無 veToken 時返回 1x

### Gauge
- [ ] 權重總和 = 100%
- [ ] 投票冷卻期
- [ ] 權重更新正確

### 緊急機制
- [ ] Emergency withdraw 有延遲
- [ ] 有適當懲罰
- [ ] 正確歸零狀態

## 真實案例

| 專案 | 問題 | 嚴重度 |
|------|------|--------|
| RAAC 2025 | 投票權計算被註釋 | Medium |
| RAAC 2025 | Boost 公式與文檔不符 | Low |
| RAAC 2025 | MAX_BOOST 重複定義 | Low |

## 參考實作

- [Curve VotingEscrow](https://github.com/curvefi/curve-dao-contracts/blob/master/contracts/VotingEscrow.vy)
- [Velodrome veNFT](https://github.com/velodrome-finance/contracts)
- [Balancer veBAL](https://github.com/balancer-labs/balancer-v2-monorepo)
