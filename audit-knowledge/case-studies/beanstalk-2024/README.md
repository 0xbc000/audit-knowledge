# Beanstalk Part 1 - 案例研究

## 基本資訊

| 項目 | 內容 |
|------|------|
| 平台 | CodeHawks |
| 時間 | 2024-02-26 ~ 2024-03-25 |
| 獎金 | $100,000 USDC |
| 程式碼行數 | ~5,776 nSLOC |
| 協議類型 | 算法穩定幣 + Staking + Gauge |
| 鏈 | Ethereum |
| 架構 | ERC-2535 Diamond |

## 協議概述

Beanstalk 是一個「信用型」算法穩定幣協議，不依賴抵押品，而是用 **信用機制** 維持 Bean 價格在 $1 附近。

### 核心概念

```
傳統穩定幣:  抵押品 → 發行穩定幣 → 價值錨定
Beanstalk:  信用激勵 → 市場行為 → 價格回歸 $1
```

### 主要組件

1. **Silo** - Staking 系統
   - 存入白名單代幣獲得 **Stalk**（治理 + 收益權）
   - Stalk 生成 **Seeds**，Seeds 產生更多 Stalk
   - **Germination** - 新存款需等待 2 個 Season 才能獲得完整權益

2. **Sun** - Season 機制
   - 每個 Season（~1 小時）調用 `gm()` 觸發
   - 根據 deltaB（價格偏離）決定鑄造或銷毀 Bean
   - 分配新 Bean 給 Fertilizer → Field → Silo

3. **Gauge System** - 動態獎勵分配
   - 自動調整不同代幣的 Stalk 產出率
   - 基於 LP 的 BDV（Bean Denominated Value）分配

4. **Field** - 借貸機制（部分 out of scope）
   - Sow Beans → 獲得 Pods
   - Pods 按隊列順序可收割

5. **Barn** - 重建機制
   - 2022 年被 hack 後的債務重組
   - Unripe Beans/LP → Fertilizer

### 關鍵術語

| 術語 | 說明 |
|------|------|
| Stalk | 治理代幣 + 收益權 |
| Seeds | 產生 Stalk 的權利 |
| Stem | 存款的時間標記 |
| BDV | Bean Denominated Value |
| Germination | 新存款的等待期 |
| Season | 時間週期 (~1h) |
| deltaB | Bean 價格與 $1 的偏差 |

## 核心參與者

| 角色 | 行為 | 風險 |
|------|------|------|
| Silo Member | 存款獲得 Stalk | 價格波動 |
| gm() Caller | 觸發新 Season | 獲得激勵 |
| Unripe Holder | 持有重建資產 | 解鎖進度 |
| Fertilizer Holder | 債務持有者 | 還款順序 |
| Pod Holder | Field 債務持有者 | 隊列位置 |

## 核心 Invariants

### 1. Stalk/Seed 計算正確性

```solidity
// Stalk 只能從以下方式獲得：
// 1. 存款時根據 BDV 發放
// 2. Seeds 隨時間產生
// 3. Convert 時保留原有 Stalk

// Invariant: 用戶 Stalk <= 初始 Stalk + 累計 Seed 產出
assert(userStalk <= initialStalk + accumulatedFromSeeds)
```

### 2. Germination 機制

```solidity
// 新存款必須等待 >= 2 Seasons
assert(deposit.germinationSeason + 2 <= currentSeason => canEarnRewards)

// Germinating 期間不能獲得分紅
assert(isGerminating => earnedBeans == 0)
```

### 3. Convert 保護

```solidity
// Above Peg: 只能 Bean → LP（減少 Bean 供應）
assert(deltaB > 0 => canConvert(Bean, LP))

// Below Peg: 只能 LP → Bean（增加 LP 深度）
assert(deltaB < 0 => canConvert(LP, Bean))

// Germinating deposits 不能 convert（防繞過）
assert(!isGerminating(deposit) => canConvert(deposit))
```

### 4. Season 獎勵分配

```solidity
// 新 Bean 分配順序正確
// 1. Fertilizer (1/3, if active)
// 2. Field (1/2 of remainder)
// 3. Silo (remainder)

assert(toFertilizer + toField + toSilo == newBeans)
```

### 5. BDV 計算一致性

```solidity
// BDV 只能在 Whitelist 時設定的函數計算
assert(bdv == calculateBDV(token, amount))

// BDV 不能被操縱
assert(bdv(t1) ≈ bdv(t2)) // 短時間內應該接近
```

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| Chainlink minAnswer | high | code-confirmed | ✅ |
| Chainlink Phase ID | high | code-confirmed | ✅ |
| ERC-1155 compliance | medium | code-confirmed | ❌ |
| Diamond Storage | medium | logic-inference | ❌ |

---

## 審計重點區域

### 1. Germination 繞過

```solidity
// ConvertFacet.sol - _withdrawTokens
// 正確檢查: 跳過 germinating 的 deposits
if (germStem.germinatingStem <= stems[i]) {
    i++;
    continue;  // 跳過 germinating deposits
}
```

**檢查點**:
- [ ] 所有 convert 路徑都檢查 germination？
- [ ] 新增白名單代幣時 germination 正確初始化？
- [ ] Season 跨越時 germination 狀態正確更新？

### 2. Gauge System 計算

```solidity
// LibGauge.sol - updateGaugePoints
// Oracle 失敗時跳過 gauge 更新
if (s.usdTokenPrice[whitelistedLpTokens[i]] == 0) {
    return (maxLpGpPerBdv, lpGpData, totalGaugePoints, type(uint256).max);
}
```

**檢查點**:
- [ ] Oracle 失敗時的 fallback 行為？
- [ ] Gauge Points 計算精度？
- [ ] 單一 LP 池時的邊界情況？

### 3. Oracle 安全性

```solidity
// LibChainlinkOracle.sol - 完整的驗證
if (roundId == 0) return 0;
if (timestamp == 0 || timestamp > currentTimestamp) return 0;
if (currentTimestamp.sub(timestamp) > CHAINLINK_TIMEOUT) return 0;
if (answer <= 0) return 0;
```

**優點**: 比很多協議的 Oracle 驗證更完整

**檢查點**:
- [ ] TWAP 計算中的 round 回溯正確？
- [ ] 多個 Oracle 的聚合邏輯？

### 4. Diamond Pattern 風險

```solidity
// AppStorage.sol - 大量狀態變數
// ~900 行的 storage layout
```

**檢查點**:
- [ ] Storage collision 風險？
- [ ] Upgrade 時的狀態遷移？
- [ ] Facet 間的狀態依賴？

### 5. Stem 計算

```solidity
// Stem 用於計算存款的「年齡」和累計獎勵
int96 stem = LibTokenSilo.stemTipForToken(token);
```

**檢查點**:
- [ ] int96 overflow/underflow？
- [ ] 負 stem 的處理？
- [ ] Stem 跨 season 的連續性？

## 歷史安全事件

### 2022 年 4 月 Governance 攻擊
- 損失: ~$182M
- 原因: Flash loan + 惡意提案
- 結果: 引入 Barn/Fertilizer 重建機制

這次審計是 Gauge System 升級，需確保：
- 不引入新的治理攻擊向量
- 不破壞現有的 Unripe 機制

## 複雜度分析

| 區域 | 複雜度 | 原因 |
|------|--------|------|
| Germination | 🔴 高 | 雙 buffer 系統，狀態轉換複雜 |
| Gauge System | 🔴 高 | 多代幣動態分配 |
| Convert | 🟡 中 | 多路徑，peg 相關限制 |
| Season/Sun | 🟡 中 | 分配邏輯清晰 |
| Oracle | 🟢 低 | 實作完整 |

## 程式碼結構

```
protocol/contracts/
├── beanstalk/
│   ├── AppStorage.sol         # 全局狀態 (~900 行)
│   ├── silo/                  # Staking 系統
│   │   ├── SiloFacet/
│   │   ├── ConvertFacet.sol
│   │   ├── WhitelistFacet/
│   │   └── EnrootFacet.sol
│   ├── sun/                   # Season 機制
│   │   ├── SeasonFacet/
│   │   ├── GaugePointFacet.sol
│   │   └── LiquidityWeightFacet.sol
│   └── barn/                  # 重建機制
│       └── UnripeFacet.sol
└── libraries/
    ├── Silo/
    │   ├── LibGerminate.sol   # Germination 邏輯
    │   ├── LibSilo.sol
    │   └── LibTokenSilo.sol
    ├── Oracle/
    │   ├── LibChainlinkOracle.sol
    │   └── LibUsdOracle.sol
    ├── LibGauge.sol           # Gauge 計算
    └── Convert/               # Convert 邏輯
```

## 發現的漏洞

### High / Medium Severity

| 漏洞 | 嚴重度 | 位置 | Pattern |
|------|--------|------|---------|
| Chainlink minAnswer 未檢查 | High | LibChainlinkOracle | [chainlink-min-max-answer.md](../../vulnerability-patterns/oracle/chainlink-min-max-answer.md) |
| Chainlink Phase ID 處理錯誤 | Medium | LibChainlinkOracle | [chainlink-phase-id.md](../../vulnerability-patterns/oracle/chainlink-phase-id.md) |
| ERC-1155 合規性問題 | Medium | SiloFacet | [erc1155-compliance.md](../../vulnerability-patterns/token/erc1155-compliance.md) |
| Diamond Storage 風險 | Medium | AppStorage | [diamond-storage-collision.md](../../vulnerability-patterns/upgrade/diamond-storage-collision.md) |

### 詳細說明

#### 1. Chainlink minAnswer 未檢查 (High)
```solidity
// LibChainlinkOracle.sol
// 當 LUNA 類事件發生時，返回 minAnswer 而非實際價格
// Venus/Blizz 2022 損失數百萬的同類漏洞
if (answer <= 0) return 0;  // ❌ 只檢查 <= 0，沒檢查 minAnswer
```

#### 2. Chainlink Phase ID 處理錯誤 (Medium)
```solidity
// TWAP 計算時簡單 roundId -= 1
// 當 Chainlink 升級聚合器時會失敗
roundId -= 1;  // ❌ Phase 變化時 roundId 跳躍 2^64
```

#### 3. ERC-1155 合規性問題 (Medium)
```solidity
// SiloFacet 的 safeTransferFrom 未調用 onERC1155Received
// 代幣可能被永久鎖定在不支持的合約中
```

#### 4. Diamond Storage 風險 (Medium)
```solidity
// AppStorage.sol ~900 行狀態變數
// 任何插入都會導致後續變數位移
// 升級時必須非常小心
```

## 已提取的 Patterns

### 新增漏洞模式 (4 個)
- `oracle/chainlink-min-max-answer.md` - Circuit Breaker 問題
- `oracle/chainlink-phase-id.md` - Phase ID 處理
- `token/erc1155-compliance.md` - ERC-1155 合規
- `upgrade/diamond-storage-collision.md` - Diamond 儲存衝突

### 新增協議類型 (1 個)
- `algorithmic-stablecoin/invariants.md` - 算法穩定幣

## 原始碼位置

本地: `audit-knowledge/source-code/2024-02-beanstalk/`

## 參考連結

- [CodeHawks 頁面](https://codehawks.cyfrin.io/c/2024-02-Beanstalk-1)
- [GitHub Repo](https://github.com/Cyfrin/2024-02-Beanstalk-1)
- [Beanstalk Docs](https://docs.bean.money/)
- [白皮書 PDF](https://bean.money/beanstalk.pdf)
- [Gauge System Proposal](https://github.com/BeanstalkFarms/Beanstalk/issues/726)
- [2022 年攻擊報告](https://rekt.news/beanstalk-rekt/)
