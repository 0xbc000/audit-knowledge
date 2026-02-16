# NFT 抵押借貸 - 核心不變量 (Invariants)

## 概述

NFT 抵押借貸協議允許用戶以 NFT 作為抵押品借入資產。與傳統 ERC20 抵押不同，NFT 具有獨特性和流動性挑戰。

### 常見組件
- **Lending Pool**: 處理存款、借款、還款
- **NFT Vault**: 保管抵押的 NFT
- **Price Oracle**: NFT 估值
- **Liquidation System**: 處理違約清算

## 必須維持的不變量

### 1. 抵押率充足 (Collateral Ratio)

```solidity
// 用戶抵押品價值必須 >= 債務 * 最低抵押率
assert(
    getUserCollateralValue(user) >= 
    getUserDebt(user) * minCollateralRatio / 100
)

// 或用健康因子表示
assert(healthFactor(user) >= MIN_HEALTH_FACTOR)
```

**違反後果**: 壞帳累積，協議 insolvency

### 2. NFT 所有權正確 (NFT Custody)

```solidity
// 抵押中的 NFT 必須在協議控制下
for each collateralized NFT:
    assert(nft.ownerOf(tokenId) == address(lendingPool))
    
// 用戶只能取回自己抵押的 NFT
assert(userCollateral[user].contains(tokenId) => user can withdraw)
```

**違反後果**: NFT 被盜或錯誤轉移

### 3. 價格有效性 (Price Validity)

```solidity
// NFT 價格必須在有效期內
assert(block.timestamp - priceOracle.lastUpdate <= MAX_STALENESS)

// 價格必須大於零
assert(nftPrice > 0)

// 價格變動在合理範圍
assert(abs(currentPrice - previousPrice) / previousPrice <= MAX_DEVIATION)
```

**違反後果**: 錯誤清算或不當借貸

### 4. 清算條件正確 (Liquidation)

```solidity
// 只有健康因子低於閾值時才能清算
assert(healthFactor(user) < LIQUIDATION_THRESHOLD => canLiquidate(user))

// 清算後健康因子應該恢復
assert(healthFactorAfterLiquidation >= MIN_HEALTH_FACTOR)

// 清算不能超額
assert(liquidationAmount <= maxLiquidationAmount)
```

**違反後果**: 錯誤清算損害用戶

### 5. 利息計算正確 (Interest Accrual)

```solidity
// 利息只能增加，不能減少（除非還款）
assert(userDebt(t) >= userDebt(t-1) || userRepaid)

// 利息計算一致（存款 vs 借款）
assert(totalInterestEarned <= totalInterestPaid + protocolRevenue)
```

**違反後果**: 資金損失或計算錯誤

### 6. 單一 NFT 風險控制

```solidity
// 單一 NFT 借款不能超過其價值的 X%
assert(borrowAmount(tokenId) <= nftValue(tokenId) * maxLTV / 100)

// 高價值 NFT 可能需要額外限制
if (nftValue > HIGH_VALUE_THRESHOLD) {
    assert(additionalCollateralRequired)
}
```

**違反後果**: 集中風險過高

## NFT 特有的審計要點

### 價格 Oracle
- [ ] NFT 價格來源可靠嗎？（鏈下？地板價？AI 估值？）
- [ ] 更新頻率足夠嗎？
- [ ] 如何處理無交易 NFT？
- [ ] 價格操縱風險（wash trading）

### 清算機制
- [ ] 清算拍賣如何進行？
- [ ] 拍賣時間是否合理？
- [ ] 如果流拍怎麼辦？
- [ ] 清算人激勵是否足夠？

### NFT 類型
- [ ] 是否支持所有 ERC721？
- [ ] ERC1155 如何處理？
- [ ] 可升級 NFT 的風險？
- [ ] 有 royalty 的 NFT？

### RWA (Real World Assets) 特有
- [ ] 鏈下資產如何驗證？
- [ ] 法律糾紛時如何處理？
- [ ] oracle 的中心化風險？
- [ ] 跨境法規問題？

## 常見漏洞模式

| 模式 | 相關不變量 | 嚴重性 | 案例 |
|------|-----------|--------|------|
| Oracle 價格過期 | #3 Price Validity | High | RAAC 2025 |
| 清算條件錯誤 | #4 Liquidation | High | - |
| NFT 轉移繞過 | #2 NFT Custody | Critical | - |
| 利息計算不一致 | #5 Interest | Medium | RAAC 2025 |
| 單一 NFT 過度借款 | #6 Risk Control | Medium | - |
| 匯率硬編碼 | #5 Interest | High | RAAC 2025 |
| 拍賣首次出價無下限 | #4 Liquidation | High | RAAC 2025 |
| 無重入保護的 ETH 轉帳 | #2 NFT Custody | High | RAAC 2025 |

## RAAC 2025 案例研究

### 發現的主要漏洞

#### 1. Oracle 價格過期未檢查
```solidity
// LendingPool.sol
function getNFTPrice(uint256 tokenId) public view returns (uint256) {
    (uint256 price, uint256 lastUpdateTimestamp) = priceOracle.getLatestPrice(tokenId);
    if (price == 0) revert InvalidNFTPrice();
    return price;  // ❌ lastUpdateTimestamp 沒用
}
```

#### 2. 匯率永遠 1:1
```solidity
// StabilityPool.sol
function getExchangeRate() public view returns (uint256) {
    // 正確邏輯被註釋掉
    return 1e18;  // ❌ 硬編碼
}
```

#### 3. 拍賣可用 1 wei 搶拍
```solidity
// NFTLiquidator.sol - placeBid()
uint256 minBidAmount = data.highestBid + (data.highestBid * minBidIncreasePercentage / 100);
// 當 highestBid = 0 時，minBidAmount = 0
if (msg.value <= minBidAmount) revert BidTooLow(minBidAmount);
// ❌ 首次可用 1 wei 出價
```

#### 4. 使用 .transfer() 轉 ETH
```solidity
// NFTLiquidator.sol
payable(data.highestBidder).transfer(data.highestBid);  // ❌ 可能失敗
```

### AI 程式碼特徵
RAAC 專案展現高度 AI 生成特徵：
- 過度完美的 NatSpec 文檔
- 重複定義的常數（MAX_BOOST 在 3 處）
- TODO/FIXME 關鍵邏輯未完成
- 文檔與實作不一致

## 審計 Prompt 模板

```markdown
## NFT 借貸協議分析

### 協議信息
- 抵押品類型: [NFT 類型]
- 借出資產: [穩定幣/ETH/其他]
- 價格 Oracle: [來源]

### 關鍵函數
[貼上 borrow/liquidate/withdraw 函數]

### 檢查項目
1. 抵押率計算是否正確？
2. NFT 價格來源是否可靠？
3. 清算觸發條件是否正確？
4. 是否有價格操縱風險？
5. 緊急情況處理機制？
```

## 參考案例
- [RAAC 2025-02](../../case-studies/raac-2025/)
- BendDAO audits
- NFTfi audits
- JPEG'd audits
