# 動態權重 AMM - Invariants 與審計要點

## 協議類型描述

動態權重 AMM（如 QuantAMM、Balancer Managed Pools）允許池子的代幣權重根據外部信號動態調整，而非傳統 AMM 的固定權重。

## 核心機制

```
傳統 AMM (Balancer):
  權重固定 → 50% ETH, 50% USDC → 永遠不變

動態權重 AMM:
  權重動態 → 50% ETH → (價格上漲) → 60% ETH → (下跌) → 45% ETH
              ↑ Oracle + 策略計算
```

### 權重調整方式

1. **即時更新**: 每次觸發時直接設置新權重
2. **線性插值**: 設置目標權重，在區塊間漸進變化
3. **時間加權**: 根據持有時間計算有效權重

## 核心參與者

| 角色 | 行為 | 風險 |
|------|------|------|
| LP | 存入流動性 | IL + 策略風險 |
| Trader | 交換代幣 | 權重變化前後套利 |
| Weight Updater | 觸發權重更新 | 時機選擇 |
| Oracle | 提供價格信號 | 價格操縱 |
| Strategy | 計算新權重 | 邏輯錯誤 |

## 核心 Invariants

### 1. 權重總和恆等於 1

```solidity
// 必須在任何時刻維持
assert(sum(weights[i] for all i) == 1e18)

// 線性插值時也必須維持
assert(sum(interpolatedWeights[i] for all i) == 1e18)
```

**違反後果**: 
- swap 計算錯誤
- 存取款金額錯誤
- 可能被套利

### 2. 權重邊界 (Guard Rails)

```solidity
// 單一代幣最小權重
assert(weight[i] >= MIN_WEIGHT)  // 通常 1% - 5%

// 單一代幣最大權重
assert(weight[i] <= MAX_WEIGHT)  // 通常 95% - 99%

// 數學表示
// MAX_WEIGHT = 1 - (numTokens - 1) * MIN_WEIGHT
```

**違反後果**:
- 極端權重導致價格操縱
- 流動性集中在單一代幣
- swap 價格滑點極端

### 3. 權重變化速度 (Epsilon)

```solidity
// 單次更新的最大變化量
assert(abs(newWeight[i] - oldWeight[i]) <= epsilonMax)

// 防止快速權重變化被套利
// 通常 epsilonMax = 1% - 5% per update
```

**違反後果**:
- 權重急變被 sandwich 攻擊
- 策略意圖被 front-run

### 4. 更新間隔

```solidity
// 兩次更新之間的最小時間
assert(block.timestamp - lastUpdate >= updateInterval)
```

**違反後果**:
- 頻繁更新增加攻擊面
- 策略無法穩定執行

### 5. Oracle 數據新鮮度

```solidity
// Oracle 時間戳在閾值內
assert(block.timestamp - oracleTimestamp <= stalenessThreshold)
```

**違反後果**:
- 使用過期價格計算權重
- 權重與市場脫節

## 常見漏洞模式

### 1. 權重正規化錯誤

```solidity
// ❌ 錯誤: 可能不等於 1
function normalizeWeights(int256[] memory weights) {
    int256 sum = 0;
    for (uint i = 0; i < weights.length; i++) {
        sum += weights[i];
    }
    for (uint i = 0; i < weights.length; i++) {
        weights[i] = weights[i] * 1e18 / sum;
    }
    // ⚠️ 精度損失可能導致 sum(weights) != 1e18
}

// ✅ 正確: 修復最後一個元素
function normalizeWeights(int256[] memory weights) {
    // ... 計算 ...
    int256 correction = 1e18 - sum(weights);
    weights[0] += correction;  // 確保總和 = 1e18
}
```

### 2. 線性插值計算錯誤

```solidity
// 插值公式
// weight(t) = startWeight + (targetWeight - startWeight) * (t - startTime) / duration

// ⚠️ 需要檢查:
// - 整數除法方向
// - t > startTime + duration 時的行為
// - 溢出風險
```

### 3. Guard Rail 邊界衝突

```solidity
// 當多個代幣同時觸及邊界
// weight[0] = MIN_WEIGHT (5%)
// weight[1] = MIN_WEIGHT (5%)
// weight[2] = ??? (必須是 90%，但 MAX_WEIGHT = 95%)

// ⚠️ 可能導致:
// - 無法滿足所有約束
// - 權重被卡在邊界
// - 需要特殊處理邏輯
```

### 4. 時間戳操縱

```solidity
// 如果可以重設 lastUpdate
function resetLastUpdate(uint256 time) external onlyManager {
    lastUpdate = time;  // ⚠️ 可繞過 updateInterval
}
```

### 5. 策略計算精度

```solidity
// 複雜的策略計算（動量、協方差等）
// 可能有:
// - 浮點數轉換錯誤
// - 除零風險
// - 溢出/下溢
```

## 審計 Checklist

### 權重機制
- [ ] 權重總和始終 = 1e18？
- [ ] Guard Rails 正確執行？
- [ ] 線性插值計算正確？
- [ ] epsilon 限制有效？
- [ ] 精度損失處理得當？

### Oracle 安全
- [ ] 價格驗證完整？(> 0, 不過期, round 完成)
- [ ] 多跳精度損失可接受？
- [ ] fallback Oracle 機制？
- [ ] 價格偏差檢查？

### 時間控制
- [ ] updateInterval 強制執行？
- [ ] 時間戳不可任意設置？
- [ ] 時間相關計算無溢出？

### 權限控制
- [ ] 誰可以觸發更新？
- [ ] 策略參數誰可以改？
- [ ] 緊急暫停機制？

### 攻擊向量
- [ ] 權重更新前後的套利？
- [ ] Oracle 操縱 + 權重變化？
- [ ] Guard Rail 邊界攻擊？

## MEV 考量

```
Block N:   讀取 Oracle 價格
Block N:   計算新權重
Block N:   設置權重（開始插值）
           ↓ 
Block N+1: 權重部分變化
           ↓ 套利者可預測權重
Block N+2: 權重繼續變化
           ...
Block N+X: 達到目標權重
```

**保護措施**:
1. 限制單次權重變化（epsilon）
2. 延長插值時間
3. 隨機化更新時間

## 測試建議

### Invariant Tests
```solidity
function invariant_weightsSumToOne() public {
    uint256 sum;
    for (uint i = 0; i < pool.numTokens(); i++) {
        sum += pool.getWeight(i);
    }
    assertEq(sum, 1e18);
}

function invariant_weightsWithinBounds() public {
    for (uint i = 0; i < pool.numTokens(); i++) {
        uint256 w = pool.getWeight(i);
        assertGe(w, MIN_WEIGHT);
        assertLe(w, MAX_WEIGHT);
    }
}
```

### Fuzz Tests
```solidity
function testFuzz_updateWeights(int256[] calldata newWeights) public {
    // 嘗試各種權重組合
    // 檢查 invariants
}
```

## 真實案例

| 專案 | 問題 | 影響 |
|------|------|------|
| QuantAMM 2024 | 時間戳可重設 | DoS / 繞過間隔 |
| QuantAMM 2024 | Multi-hop 精度損失 | 價格偏差 |

## 參考實作

- [QuantAMM](https://github.com/Cyfrin/2024-12-quantamm)
- [Balancer Managed Pools](https://github.com/balancer/balancer-v2-monorepo)
- [Gyroscope](https://github.com/gyrostable/concentrated-lps)
