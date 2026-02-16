# QuantAMM - 案例研究

## 基本資訊

| 項目 | 內容 |
|------|------|
| 平台 | CodeHawks |
| 時間 | 2024-12-20 ~ 2025-01-15 |
| 獎金 | 49,600 OP |
| 程式碼行數 | ~3,000 nSLOC |
| 協議類型 | AMM + 動態權重 + Oracle |
| 鏈 | EVM (Balancer V3 整合) |

## 協議概述

QuantAMM 是建構在 Balancer V3 上的「動態權重 AMM」，核心創新是 **TFMM (Temporal Function Market Making)**：

### 核心概念
- **傳統 AMM**: 權重固定 (如 50/50 ETH/USDC)
- **QuantAMM**: 權重根據價格訊號動態調整，自動「追漲」或「防守」

### 核心機制

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Chainlink      │────▶│ UpdateWeight     │────▶│ QuantAMM        │
│  Oracles        │     │ Runner           │     │ WeightedPool    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
   價格數據              策略計算 + Guard Rails       權重線性插值
```

### 主要組件

1. **UpdateWeightRunner** (Singleton)
   - 協調所有池子的權重更新
   - 管理 Oracle、策略規則
   - 權重 Guard Rails 執行

2. **QuantAMMWeightedPool**
   - 繼承 Balancer V3 的 Weighted Pool
   - 權重在區塊間線性插值
   - 儲存壓縮的權重和乘數

3. **Update Rules** (策略)
   - `MomentumUpdateRule` - 動量策略
   - `AntimomentumUpdateRule` - 逆向策略
   - `MinimumVarianceUpdateRule` - 最小變異策略
   - `ChannelFollowingUpdateRule` - 通道追蹤

4. **Oracles**
   - `ChainlinkOracle` - 標準 Chainlink 封裝
   - `MultiHopOracle` - 多跳價格計算

## 關鍵參與者

| 角色 | 行為 | 風險 |
|------|------|------|
| LP | 存入流動性 | IL + 策略風險 |

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| Oracle staleness | medium | code-confirmed | ❌ |
| MultiHop precision | medium | code-confirmed | ❌ |
| Weight normalization | medium | logic-inference | ❌ |
| Timestamp reset | medium | code-confirmed | ❌ |
| Storage compression | low | logic-inference | ❌ |
| Trader | 交換代幣 | MEV |
| Pool Runner | 觸發權重更新 | 可被任何人觸發 |
| quantammAdmin | 管理 Oracle、費用 | 中心化風險 |
| Pool Manager | 管理單一池子 | 可重設時間戳 |

## 核心 Invariants

### 1. 權重總和 = 1

```solidity
// 所有代幣權重總和必須等於 1e18
assert(sum(weights[i] for all i) == 1e18)
```

### 2. 權重在 Guard Rails 內

```solidity
// 單一代幣權重不能低於 absoluteWeightGuardRail
assert(weight[i] >= absoluteWeightGuardRail)

// 單一代幣權重不能高於 1 - (n-1) * absoluteWeightGuardRail
assert(weight[i] <= 1e18 - (numTokens - 1) * absoluteWeightGuardRail)
```

### 3. 權重變化速度限制 (Epsilon)

```solidity
// 單次更新的權重變化不能超過 epsilonMax
assert(abs(newWeight[i] - oldWeight[i]) <= epsilonMax)
```

### 4. Oracle 數據新鮮度

```solidity
// Oracle 時間戳必須在 staleness threshold 內
assert(block.timestamp - oracleTimestamp <= oracleStalenessThreshold)
```

### 5. 更新間隔

```solidity
// 兩次更新之間必須間隔足夠時間
assert(block.timestamp - lastPoolUpdateRun >= updateInterval)
```

## 審計重點區域

### 1. Oracle 安全性

#### ChainlinkOracle.sol - 缺少完整驗證
```solidity
function _getData() internal view override returns (int216, uint40) {
    (, int data, , uint timestamp, ) = priceFeed.latestRoundData();
    require(data > 0, "INVLDDATA");
    // ⚠️ 沒有檢查：
    // - roundId vs answeredInRound (stale round)
    // - startedAt > 0
    // - timestamp > 0
    // - 價格合理範圍
    data = data * int(10 ** normalizationFactor);
    return (int216(data), uint40(timestamp));
}
```

**潛在問題**: 可能返回過期或異常價格

#### MultiHopOracle.sol - 精度損失
```solidity
if (oracleConfig.invert) {
    data = (data * 10 ** 18) / oracleRes;  // ⚠️ 除法截斷
} else {
    data = (data * oracleRes) / 10 ** 18;  // ⚠️ 除法截斷
}
```

**潛在問題**: 多跳計算累積精度損失

### 2. 權重計算邏輯

#### QuantammMathGuard.sol - 正規化邊界

```solidity
function _clampWeights(...) internal pure returns (int256[] memory) {
    // ...
    if (sumOtherWeights != 0) {
        int256 proportionalRemainder = sumRemainerWeight.div(sumOtherWeights);
        for (uint i; i < weightLength; ++i) {
            if (_weights[i] != absoluteMin) {
                _weights[i] = _weights[i].mul(proportionalRemainder);
            }
        }
    }
    // ⚠️ 如果所有權重都等於 absoluteMin，這個分支不會執行
    // 權重總和可能不等於 1
}
```

**潛在問題**: 極端情況下權重正規化可能失敗

#### 修復最後權重以確保總和為 1

```solidity
// QuantammMathGuard.sol - _normalizeWeightUpdates
_newWeights[0] = _newWeights[0] + (ONE - newWeightsSum);
// ⚠️ 註釋說可能破壞 guard rail，只差 1e-18
// 但累積效應？
```

### 3. 權限和時間戳操作

#### InitialisePoolLastRunTime - 重設攻擊

```solidity
function InitialisePoolLastRunTime(address _poolAddress, uint40 _time) external {
    // Pool Manager 可以重設 lastPoolUpdateRun
    // 這可以用來繞過 updateInterval 限制
}
```

**潛在問題**: 
- 設為未來時間可以阻止更新
- 設為過去時間可以觸發多次更新

### 4. 線性插值 + Guard Rail 交互

```solidity
// UpdateWeightRunner.sol
// 計算到達 guard rail 的時間
if (blockMultiplier > int256(0)) {
    weightBetweenTargetAndMax = upperGuardRail - local.currentWeights[i];
    blockTimeUntilGuardRailHit = weightBetweenTargetAndMax / blockMultiplier;
}
```

**潛在問題**: 
- 複雜的時間計算可能有 off-by-one
- 當接近 guard rail 時行為是否正確？

### 5. 儲存壓縮 (9 dp)

```solidity
// 權重從 18dp 壓縮到 9dp 儲存
// 4 個權重 + 4 個乘數 = 1 個 int256 slot
```

**潛在問題**:
- 精度損失影響長期運行
- 解壓縮後可能不等於原始值

## 數學密集區域

### PRBMathSD59x18 使用

```solidity
// 多處使用高精度數學
import "@prb/math/contracts/PRBMathSD59x18.sol";

// 可能的溢出/下溢點：
_x.log2()     // x <= 0 會 revert
_y.mul(_x.log2()).exp2()  // 極大/極小值
```

### Moving Average 計算

```solidity
// QuantammMathMovingAverage.sol
// EMA 計算：newAvg = lambda * newValue + (1 - lambda) * oldAvg
```

**檢查點**:
- Lambda 邊界 (0, 1)
- 首次計算 (oldAvg = 0?)

## 特殊攻擊向量

### 1. Oracle 操縱 + 權重

如果攻擊者能操縱 Oracle 價格：
1. 觸發大幅權重變化（受 epsilonMax 限制）
2. 套利新權重
3. 在 updateInterval 後重複

### 2. MEV - 權重更新前後

```
Block N: 權重 50/50
           ↓ 有人觸發 performUpdate()
Block N: 權重目標 60/40，開始插值
Block N+1: 權重 ~51/49
           ↓ 套利者交易
```

### 3. Guard Rail 邊界

將多個代幣推到 guard rail 邊界：
- 可能導致不可預期的權重分配
- 可能卡在邊界無法回來

## 程式碼結構

```
pkg/pool-quantamm/contracts/
├── ChainlinkOracle.sol          # Chainlink 封裝
├── MultiHopOracle.sol           # 多跳 Oracle
├── QuantAMMStorage.sol          # 壓縮儲存
├── QuantAMMWeightedPool.sol     # 主池合約
├── QuantAMMWeightedPoolFactory.sol
├── UpdateWeightRunner.sol       # 核心協調器
└── rules/
    ├── UpdateRule.sol           # 規則基類
    ├── MomentumUpdateRule.sol
    ├── AntimomentumUpdateRule.sol
    ├── ChannelFollowingUpdateRule.sol
    ├── MinimumVarianceUpdateRule.sol
    └── base/
        ├── QuantammMathGuard.sol        # Guard Rails
        ├── QuantammMathMovingAverage.sol
        ├── QuantammBasedRuleHelpers.sol
        ├── QuantammVarianceBasedRule.sol
        └── QuantammGradientBasedRule.sol
```

## 需要提取的 Patterns

### 新增漏洞模式

1. **動態權重正規化錯誤**
   - 類別: `math/normalization-error.md`
   - 權重總和必須 = 1 的不變量

2. **Oracle 多跳精度損失**
   - 類別: `oracle/multi-hop-precision.md`
   - 連續除法的精度累積問題

3. **時間戳重設攻擊**
   - 類別: `access-control/timestamp-manipulation.md`
   - 可重設的時間戳導致繞過間隔限制

### 新增協議類型

- `protocol-patterns/dynamic-amm/invariants.md`
  - 權重 AMM 的核心不變量
  - Guard Rails 設計模式
  - 線性插值的安全考量

## 原始碼位置

本地: `audit-knowledge/source-code/2024-12-quantamm/`

## 參考連結

- [CodeHawks 頁面](https://codehawks.cyfrin.io/c/2024-12-quantamm)
- [GitHub Repo](https://github.com/Cyfrin/2024-12-quantamm)
- [QuantAMM 白皮書](https://www.quantamm.fi/research)
- [TFMM 論文](https://arxiv.org/abs/2404.15489)
