# 算法穩定幣 - Invariants 與審計要點

## 協議類型描述

算法穩定幣通過機制設計（而非抵押品）維持價格穩定。主要類型：

| 類型 | 範例 | 機制 |
|------|------|------|
| 鑄幣稅型 | Beanstalk | 信用激勵 + 債務 |
| 雙幣型 | Terra/UST | 套利 + 治理幣 |
| Rebase 型 | Ampleforth | 供應彈性調整 |
| 部分抵押型 | Frax | 抵押 + 算法 |

## 核心機制（以 Beanstalk 為例）

```
價格 > $1 (Above Peg):
  → 鑄造新 Bean
  → 分配給 Stakers (稀釋)
  → 供應增加 → 價格下降

價格 < $1 (Below Peg):
  → 發行債務 (Soil/Pods)
  → 用戶借 Bean 給協議
  → 供應減少 → 價格上升
```

## 核心參與者

| 角色 | 行為 | 動機 |
|------|------|------|
| Staker | 存入資產賺取收益 | 通膨獎勵 |
| Lender | 借出穩定幣 | 債務利息 |
| Arbitrageur | 套利價格偏離 | 利潤 |
| LP | 提供流動性 | 手續費 |

## 核心 Invariants

### 1. Peg 維護機制

```solidity
// Above Peg: 必須增加供應
assert(deltaB > 0 => canMintNewTokens)

// Below Peg: 必須減少供應或增加需求
assert(deltaB < 0 => canIssueDebt || canIncentivizeBurn)

// Peg 偏差必須能被計算
assert(deltaB == calculateDeltaB(spotPrice, pegPrice))
```

### 2. 供應計算正確性

```solidity
// 總供應 = 流通 + 鎖定 + 債務
assert(totalSupply == circulating + staked + owed)

// 新鑄造正確分配
assert(newMint == toStakers + toDebtHolders + toTreasury)
```

### 3. 債務系統

```solidity
// 債務必須按順序償還
assert(debtQueue.order == FIFO || debtQueue.order == specified)

// 債務利率在合理範圍
assert(debtInterestRate <= maxRate && debtInterestRate >= 0)

// 債務總額追蹤正確
assert(totalDebt == sum(individualDebts))
```

### 4. Staking 獎勵

```solidity
// 獎勵只能來自新鑄造（Above Peg）
assert(rewards > 0 => deltaB > 0 || fromReserve)

// 獎勵按權重正確分配
assert(userReward == totalReward * userShare / totalShare)

// 等待期正確執行
assert(deposit.age >= minAge => canClaimReward)
```

### 5. Oracle 安全

```solidity
// 價格來源可靠
assert(priceOracle.isValid())

// TWAP 防止操縱
assert(useTWAP || checkDeviation(spot, twap))

// 多源聚合
assert(price == median(sources) || weightedAverage(sources))
```

## 常見漏洞模式

### 1. Oracle 操縱 → Peg 攻擊

```solidity
// 攻擊流程:
// 1. Flash loan 大量資金
// 2. 操縱 LP 價格
// 3. 觸發 Above Peg 鑄造
// 4. 獲得新鑄造的代幣
// 5. 歸還 flash loan

// 防護: TWAP, 多源 Oracle, 延遲
```

### 2. 等待期繞過

```solidity
// ❌ 錯誤: 可通過 convert 繞過 germination
function convert(deposit) {
    // 沒檢查是否在等待期
    processConvert(deposit);
}

// ✅ 正確: 檢查等待期
function convert(deposit) {
    require(!isGerminating(deposit), "Still germinating");
    processConvert(deposit);
}
```

### 3. 債務隊列攻擊

```solidity
// 攻擊: 搶佔隊列前端位置
// 影響: 正常用戶的債務無法償還

// 防護: 
// - 最小購買量
// - 時間加權
// - 分批處理
```

### 4. 死亡螺旋

```solidity
// 當 Below Peg 時間過長:
// 1. 用戶失去信心
// 2. 大量賣出
// 3. 價格進一步下跌
// 4. 更多人賣出
// 5. 協議崩潰

// 防護:
// - 儲備金
// - 熔斷機制
// - 逐步調整
```

### 5. 治理攻擊

```solidity
// Beanstalk 2022 案例:
// 1. Flash loan 獲得治理權
// 2. 提交惡意提案
// 3. 立即執行
// 4. 提取所有資金

// 防護:
// - 時間鎖
// - 提案延遲
// - Flash loan 防護
```

## 審計 Checklist

### Peg 機制
- [ ] Above/Below Peg 判斷正確？
- [ ] 鑄造/銷毀邏輯正確？
- [ ] 調整幅度有限制？

### Oracle
- [ ] 使用 TWAP？
- [ ] 多源驗證？
- [ ] 失敗時的 fallback？

### 等待期/Vesting
- [ ] 所有路徑都檢查等待期？
- [ ] 等待期狀態正確更新？
- [ ] 無法通過 convert/transfer 繞過？

### 債務系統
- [ ] 隊列順序正確？
- [ ] 利率計算正確？
- [ ] 總債務追蹤正確？

### 治理安全
- [ ] 提案有延遲？
- [ ] Flash loan 無法影響投票？
- [ ] 緊急暫停機制？

### 經濟攻擊
- [ ] 單區塊內無法套利？
- [ ] 大額操作有限制？
- [ ] 價格偏差有保護？

## 經濟模型風險

| 風險 | 觸發條件 | 後果 |
|------|---------|------|
| 死亡螺旋 | 長期 Below Peg | 協議崩潰 |
| 通膨失控 | 持續 Above Peg | 價值稀釋 |
| 債務堆積 | 無人購買債務 | 無法恢復 Peg |
| 治理失效 | 代幣集中 | 惡意提案 |

## 測試建議

### Invariant Tests
```solidity
function invariant_supplyConsistency() public {
    uint256 total = coin.totalSupply();
    uint256 staked = silo.totalStaked();
    uint256 circulating = coin.balanceOf(address(0)) - total + staked;
    assertEq(total, staked + circulating);
}

function invariant_debtQueue() public {
    // 債務按順序
    for (uint i = 1; i < debtQueue.length; i++) {
        assertLe(debtQueue[i-1].createdAt, debtQueue[i].createdAt);
    }
}
```

### 經濟模擬
- Above/Below Peg 的長期行為
- 極端市場條件下的穩定性
- 大戶攻擊場景

## 真實案例

| 專案 | 年份 | 問題 | 損失 |
|------|------|------|------|
| Beanstalk | 2022 | 治理攻擊 | $182M |
| Terra/UST | 2022 | 死亡螺旋 | $40B+ |
| Iron Finance | 2021 | 銀行擠兌 | $2B |
| Basis Cash | 2021 | 無法恢復 Peg | - |

## 參考實作

- [Beanstalk](https://github.com/BeanstalkFarms/Beanstalk)
- [Frax](https://github.com/FraxFinance)
- [Ampleforth](https://github.com/ampleforth)
