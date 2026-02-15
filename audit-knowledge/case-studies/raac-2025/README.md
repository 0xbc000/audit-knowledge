# RAAC Core Contracts - 案例研究

## 🤖 AI 生成程式碼特徵分析

### 判定結論：**高度疑似 AI 生成**

經深入分析，RAAC 專案展現多項典型的 AI 生成程式碼特徵：

---

### 🔴 紅旗 #1: 過度完美的文檔結構

每個合約都有：
- 完整 NatSpec 註釋
- 統一格式的 `@title`, `@author`, `@notice`, `@dev`
- "Key features:" 列表格式
- 每個函數都有參數和返回值說明

**範例 (veRAACToken.sol):**
```solidity
/**
 * @title Vote Escrowed RAAC Token
 * @author RAAC Protocol Team
 * @notice A vote-escrowed token contract that allows users to lock RAAC tokens...
 * @dev Implementation of vote-escrowed RAAC (veRAAC) with time-weighted voting power...
 * Key features:
 * - Users can lock RAAC tokens for voting power
 * - Voting power decays linearly over time
 * - Includes emergency withdrawal mechanisms
 * - Integrates with governance for proposal voting
 * - Provides boost calculations for rewards
 */
```

**問題**: 真實開發者很少寫這麼「完美」的註釋，尤其是整個專案都一致。

---

### 🔴 紅旗 #2: 複製貼上的初始化模式

多個合約使用幾乎相同的初始化函數名稱和結構：

```solidity
// veRAACToken.sol
function _initializeBoostParameters() internal {
    _boostState.maxBoost = MAX_BOOST;
    _boostState.minBoost = MIN_BOOST;
    _boostState.boostWindow = 7 days;
    _boostState.baseWeight = 1e18;
}

function _initializeLockParameters() internal {
    _lockState.minLockDuration = MIN_LOCK_DURATION;
}

// GaugeController.sol
function _initializeRoles() private { ... }
function _initializeBoostParameters() private { ... }
function _initializeTypeWeights() private { ... }
```

**問題**: AI 喜歡建立「模板式」的函數結構，缺乏人類開發者的個人風格變化。

---

### 🔴 紅旗 #3: 過度工程化的常數定義

每個數字都定義成常數，但很多重複或不一致：

```solidity
// veRAACToken.sol
uint256 public constant MIN_LOCK_DURATION = 365 days;
uint256 public constant MAX_LOCK_DURATION = 1460 days;
uint256 public constant MAX_BOOST = 25000;
uint256 public constant MIN_BOOST = 10000;

// GaugeController.sol (重複定義！)
uint256 public constant MAX_BOOST = 25000;
uint256 public constant MIN_BOOST = 10000;

// BoostController.sol (又重複！)
uint256 public constant MAX_BOOST = 25000;
uint256 public constant MIN_BOOST = 10000;
```

**問題**: 真正的開發者會抽出共用常數到一個地方。AI 傾向在每個需要的地方重新定義。

---

### 🔴 紅旗 #4: 「FIXME」和未完成邏輯

關鍵業務邏輯被註釋掉或標記為待完成：

```solidity
// VotingPowerLib.sol - 核心計算被註釋！
// FIXME: Get me to uncomment me when able
// bias = RAACVoting.calculateBias(amount, unlockTime, block.timestamp);
// slope = RAACVoting.calculateSlope(amount);

// StabilityPool.sol - 硬編碼匯率
function getExchangeRate() public view returns (uint256) {
    // uint256 totalDeCRVUSD = deToken.totalSupply();
    // return (totalRcrvUSD * scalingFactor) / totalDeCRVUSD;
    return 1e18;  // ❌ 永遠 1:1
}

// StabilityPool.sol - TODO 未完成
// TODO: Logic for distributing to managers based on allocation
```

**問題**: AI 經常產生「骨架程式碼」，人類需要填補實際邏輯但沒做。

---

### 🔴 紅旗 #5: 文檔與實作不一致

**BoostCalculator.sol 範例:**
- 註釋說「Implements Curve-style boost calculations」
- 但實際 boost 計算只是簡單的線性比例，不是 Curve 風格

**LendingPool.sol 範例:**
- 取得 `lastUpdateTimestamp` 但完全沒用
```solidity
(uint256 price, uint256 lastUpdateTimestamp) = priceOracle.getLatestPrice(tokenId);
if (price == 0) revert InvalidNFTPrice();
return price;  // lastUpdateTimestamp 被丟棄
```

---

### 🔴 紅旗 #6: Library 設計過度複雜

建立了大量 library，但使用方式混亂：

```
libraries/
├── governance/
│   ├── BoostCalculator.sol   (165 行)
│   ├── Checkpoints.sol       (87 行)
│   ├── LockManager.sol       (150+ 行)
│   ├── PowerCheckpoint.sol   (100+ 行)
│   ├── RAACVoting.sol        (80+ 行)
│   └── VotingPowerLib.sol    (200+ 行)
└── math/
    ├── PercentageMath.sol
    ├── TimeWeightedAverage.sol
    └── WadRayMath.sol
```

**問題**: 這些 library 功能重疊，很多函數從未被調用。AI 喜歡建立「看起來專業」的架構。

---

### 🔴 紅旗 #7: 安全漏洞的「教科書式」錯誤

| 漏洞 | 位置 | AI 特徵 |
|------|------|---------|
| 使用 `.transfer()` 而非 `call` | NFTLiquidator.sol | 過時的最佳實踐 |
| 無 ReentrancyGuard | NFTLiquidator.sol | 看似完整但缺關鍵保護 |
| Oracle 無過期檢查 | LendingPool.sol | 取得資料但不用 |
| 首次出價無下限 | NFTLiquidator.sol | 邊界條件漏洞 |

---

### 🔴 紅旗 #8: 過度防禦性但錯失關鍵

```solidity
// 過度檢查（到處都是）
if (_veToken == address(0)) revert InvalidPool();
if (amount == 0) revert InvalidAmount();
if (newRate > MAX_TAX_RATE) revert TaxRateExceedsLimit();

// 但漏掉關鍵的
// ❌ 沒檢查 oracle 價格是否過期
// ❌ 沒檢查 highestBid == 0 時的首次出價
// ❌ 沒有重入保護在 ETH 轉帳前
```

---

### 🟡 其他 AI 特徵

1. **變數命名過度一致**: `_initializeX`, `_updateX`, `calculateX` 
2. **import 過多**: 每個檔案 import 10+ 個依賴，很多沒用到
3. **Role-based access 濫用**: 定義了很多 role 但權限設計不合理
4. **事件設計冗餘**: 很多事件永遠不會被 emit

---

### 📊 AI 生成機率評估

| 特徵 | 權重 | 分數 |
|------|------|------|
| 文檔過度完美 | 15% | 95/100 |
| 重複常數定義 | 10% | 90/100 |
| TODO/FIXME 關鍵邏輯 | 20% | 100/100 |
| 文檔與實作不符 | 20% | 85/100 |
| 過度工程化架構 | 15% | 90/100 |
| 教科書式漏洞 | 20% | 95/100 |

**總評: ~92% 機率為 AI 生成**

---

## 基本資訊

| 項目 | 內容 |
|------|------|
| 平台 | CodeHawks |
| 時間 | 2025-02-03 ~ 2025-02-24 |
| 獎金 | $77,280 USDC |
| 程式碼行數 | ~3,864 nSLOC |
| 協議類型 | RWA (Real World Assets) + NFT + Lending |
| 鏈 | EVM Compatible |

## 協議概述

RAAC 是將房地產資產上鏈的 DeFi 協議，核心組件：

### 核心機制
1. **RAAC NFT**: 代表房產的 NFT
2. **Lending Pool**: 
   - 用戶可以抵押 RAAC NFT 借出 crvUSD
   - 存款人獲得 RToken
3. **Stability Pool**: 
   - 用戶存入 RToken 獲得 deToken
   - 處理清算
4. **veRAACToken**: 治理代幣，鎖倉獲得投票權和 boost
5. **Gauge System**: 雙 gauge 系統（RAACGauge + RWAGauge）

### 關鍵參與者
- **NFT Owner**: 持有房產 NFT，可抵押借貸
- **Lender**: 存入 crvUSD 賺取利息
- **Borrower**: 抵押 NFT 借入 crvUSD
- **Oracle**: 更新房價和利率

## 發現的漏洞

## Evidence Quality

| Finding | Confidence | Evidence Type | Verified |
|---------|-----------|---------------|----------|
| H-01 (oracle staleness) | high | code-confirmed | ✅ |
| H-02 (hardcoded rate) | high | code-confirmed | ✅ |
| H-03 (no reentrancy guard) | high | code-confirmed | ✅ |
| H-04 (.transfer) | high | code-confirmed | ✅ |
| H-05 (auction first bid) | high | code-confirmed | ✅ |
| M-06 (interest mismatch) | medium | code-confirmed | ❌ |
| M-07 (TODO) | high | code-confirmed | ✅ |
| M-08 (liquidation bypass) | medium | logic-inference | ❌ |

---

### Critical / High Severity

#### 1. Oracle 價格無過期檢查
- **檔案**: `LendingPool.sol` → `getNFTPrice` (Line 591-594)
- **問題**: 取得 `lastUpdateTimestamp` 但未使用
- **程式碼**:
```solidity
function getNFTPrice(uint256 tokenId) public view returns (uint256) {
    (uint256 price, uint256 lastUpdateTimestamp) = priceOracle.getLatestPrice(tokenId);
    if (price == 0) revert InvalidNFTPrice();
    return price;  // ❌ lastUpdateTimestamp 完全沒用
}
```
- **影響**: 使用過期價格導致錯誤清算或不當借貸
- **Pattern**: [oracle-staleness.md](../../vulnerability-patterns/oracle/oracle-staleness.md)

#### 2. 匯率硬編碼（正確邏輯被註釋）
- **檔案**: `StabilityPool.sol` → `getExchangeRate` (Line 210-219)
- **問題**: 返回硬編碼 `1e18`，正確計算邏輯被註釋掉
- **程式碼**:
```solidity
function getExchangeRate() public view returns (uint256) {
    // uint256 totalDeCRVUSD = deToken.totalSupply();
    // uint256 totalRcrvUSD = rToken.balanceOf(address(this));
    // return (totalRcrvUSD * scalingFactor) / totalDeCRVUSD;
    return 1e18;  // ❌ 永遠返回 1:1
}
```
- **影響**: 嚴重套利漏洞、用戶資金損失
- **Pattern**: [hardcoded-values.md](../../vulnerability-patterns/business-logic/hardcoded-values.md)

#### 3. NFTLiquidator 無重入保護
- **檔案**: `NFTLiquidator.sol`
- **問題**: 合約未繼承 `ReentrancyGuard`，但有多個 ETH 轉帳
- **危險函數**:
  - `placeBid()` - Line 127: 退還前一個出價者
  - `endAuction()` - Line 151: 轉帳給 StabilityPool
  - `buyBackNFT()` - Line 171, 177, 180: 多次 ETH 轉帳
- **影響**: 重入攻擊可能導致資金被盜

#### 4. 使用 `.transfer()` 轉帳 ETH
- **檔案**: `NFTLiquidator.sol` (Lines 127, 151, 171, 177, 180)
- **問題**: 使用 `payable(addr).transfer(amount)` 而非 `call`
- **程式碼**:
```solidity
payable(data.highestBidder).transfer(data.highestBid);  // ❌ 可能失敗
payable(stabilityPool).transfer(winningBid);             // ❌ 可能失敗
```
- **影響**: 如果接收者是合約且 fallback 消耗 >2300 gas，轉帳失敗

#### 5. 拍賣首次出價無最低限制
- **檔案**: `NFTLiquidator.sol` → `placeBid()` (Line 123)
- **問題**: 當 `highestBid == 0` 時，`minBidAmount` 也是 0
- **程式碼**:
```solidity
uint256 minBidAmount = data.highestBid + (data.highestBid * minBidIncreasePercentage / 100);
// 當 highestBid = 0 時，minBidAmount = 0 + 0 = 0
if (msg.value <= minBidAmount) revert BidTooLow(minBidAmount);
// 所以首次出價 1 wei 即可
```
- **影響**: 攻擊者可用 1 wei 搶拍

### Medium Severity

#### 6. 利息計算不一致
- **檔案**: `ReserveLibrary.sol` (Lines 113-127)
- **問題**: 存款用線性計算，借款用複利計算
- **程式碼**:
```solidity
// 線性計算存款利息
reserve.liquidityIndex = calculateLiquidityIndex(...);  // linear
// 複利計算借款利息
reserve.usageIndex = calculateUsageIndex(...);          // compound
```
- **影響**: 長期運行產生 dust 累積

#### 7. TODO 未完成
- **檔案**: `StabilityPool.sol` (Line 334)
- **程式碼**:
```solidity
// TODO: Logic for distributing to managers based on allocation
```
- **影響**: 功能未實現，可能導致資金分配問題

#### 8. 清算邏輯可被繞過
- **檔案**: `LendingPool.sol`
- **問題**: `initiateLiquidation` 和 `finalizeLiquidation` 之間的 grace period 可能被利用
- **影響**: 用戶可在 grace period 內操作避免清算

### Low Severity

#### 9. 缺少事件記錄
- **檔案**: 多個合約
- **問題**: 某些關鍵狀態變更未 emit 事件

#### 10. Magic Numbers
- **檔案**: 多個合約
- **問題**: 硬編碼的數字沒有常數定義
- **範例**: `3 days`, `11 / 10` (110%), `1e6` 等

### 新增發現的漏洞

#### 11. VotingPowerLib 核心計算被註釋
- **檔案**: `VotingPowerLib.sol` (Line 79-80)
- **問題**: 核心的 bias/slope 計算被註釋，用了簡化版本
- **程式碼**:
```solidity
// FIXME: Get me to uncomment me when able
// bias = RAACVoting.calculateBias(amount, unlockTime, block.timestamp);
// slope = RAACVoting.calculateSlope(amount);

// 實際使用的是簡化版：
uint256 duration = unlockTime - block.timestamp;
uint256 initialPower = (amount * duration) / MAX_LOCK_DURATION;
bias = int128(int256(initialPower));
```
- **影響**: 投票權計算可能與設計意圖不符

#### 12. 常數重複定義
- **檔案**: veRAACToken.sol, BoostController.sol, GaugeController.sol
- **問題**: `MAX_BOOST`, `MIN_BOOST` 在多處重複定義
- **風險**: 未來維護時可能改一處漏其他

#### 13. StabilityPool 的 Manager 分配邏輯未實現
- **檔案**: `StabilityPool.sol` (Line 334)
- **程式碼**:
```solidity
// TODO: Logic for distributing to managers based on allocation
```
- **影響**: 管理者的資金分配功能無法運作

#### 14. RAACMinter 的 excessTokens 邏輯有問題
- **檔案**: `RAACMinter.sol` → `mintRewards()`
- **問題**: excessTokens 的扣減邏輯可能導致會計錯誤
- **程式碼**:
```solidity
uint256 toMint = excessTokens >= amount ? 0 : amount - excessTokens;
excessTokens = excessTokens >= amount ? excessTokens - amount : 0;
```
- **影響**: 如果 excessTokens > amount，則 toMint=0 但仍 transfer amount

#### 15. GaugeController 的 VOTE_DELAY 常數矛盾
- **檔案**: `GaugeController.sol`
- **問題**: 
```solidity
uint256 public constant VOTE_DELAY = 10 days;
uint256 public constant MIN_VOTE_DELAY = 1 days;
uint256 public constant MAX_VOTE_DELAY = 10 days;
```
- VOTE_DELAY 設為最大值，MIN/MAX 沒被用到

## 關鍵 Invariants

```solidity
// 1. NFT 價格必須在有效期內
assert(block.timestamp - priceOracle.lastUpdateTimestamp <= MAX_STALENESS)

// 2. 健康因子低於閾值才能清算
assert(healthFactor < LIQUIDATION_THRESHOLD => canLiquidate)

// 3. 抵押率必須足夠
assert(userCollateralValue >= userDebt * minCollateralRatio)

// 4. veToken 投票權隨時間衰減
assert(votingPower(t) <= votingPower(t-1)) // for locked tokens

// 5. 總鎖倉量不超過上限
assert(totalLocked <= MAX_TOTAL_LOCKED_AMOUNT)
```

## 協議類型特有的審計要點

### RWA (Real World Assets) 協議
- [ ] 資產價格 oracle 的更新頻率和可靠性
- [ ] 鏈下資產和鏈上代幣的對應關係
- [ ] 清算時現實資產如何處理

### NFT 抵押借貸
- [ ] NFT 價格估值機制
- [ ] 單一 NFT 的流動性風險
- [ ] 清算拍賣機制

### veToken 機制
- [ ] 鎖倉期限計算正確性
- [ ] 投票權衰減邏輯
- [ ] emergency withdraw 安全性
- [ ] boost 計算精度

## 程式碼結構

```
contracts/
├── core/
│   ├── pools/
│   │   ├── LendingPool/     # NFT 抵押借貸
│   │   └── StabilityPool/   # 穩定池 + 清算
│   ├── tokens/
│   │   ├── RAACNFT.sol      # 房產 NFT
│   │   ├── veRAACToken.sol  # 投票鎖倉代幣
│   │   ├── RToken.sol       # 存款憑證
│   │   └── DebtToken.sol    # 債務代幣
│   ├── oracles/
│   │   ├── RAACHousePriceOracle.sol
│   │   └── RAACPrimeRateOracle.sol
│   └── governance/
│       ├── gauges/          # 雙 gauge 系統
│       └── proposals/       # 治理提案
└── libraries/
    └── math/                # 數學庫
```

## 原始碼位置

本地 clone: `/Users/billyc/clawd/raac-audit/2025-02-raac/`

## 漏洞統計

| 嚴重度 | 數量 | 典型 AI 錯誤 |
|--------|------|-------------|
| Critical/High | 5 | Oracle 未驗證、硬編碼邏輯、無重入保護 |
| Medium | 3 | 利息計算不一致、TODO 未完成、清算繞過 |
| Low | 7 | Magic numbers、事件缺失、常數重複 |
| **總計** | **15** | |

## AI 生成程式碼的審計策略

### 重點檢查項目
1. **所有 TODO/FIXME 註釋** - AI 常留下未完成的邏輯
2. **被註釋的程式碼** - 可能是「正確」的實作被跳過
3. **文檔說的功能是否真的實現** - 檢查 @notice/@dev 與實際邏輯
4. **邊界條件** - AI 常忽略 0 值、首次操作、極端情況
5. **重複定義的常數** - 可能有不一致
6. **Library 函數是否被使用** - 很多可能是死代碼

### AI 程式碼的優勢（審計時）
- 結構清晰容易理解
- 命名規範一致
- 註釋完整
- 容易找到 pattern

### AI 程式碼的劣勢（審計重點）
- 業務邏輯可能是「假的」
- 安全檢查可能不完整
- 邊界條件處理差
- 容易有 copy-paste 錯誤

## 參考連結

- [CodeHawks 結果頁面](https://codehawks.cyfrin.io/c/2025-02-raac/results)
- [GitHub Repo](https://github.com/Cyfrin/2025-02-raac)
- 本地原始碼: `audit-knowledge/source-code/2025-02-raac/`
