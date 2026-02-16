# Case Studies Index

> 12 個真實審計案例，按協議類型分類

## 總覽

| 案例 | 類型 | 平台 | 獎金 | Findings | 關鍵漏洞 |
|------|------|------|------|----------|----------|
| olas-2026 | Tokenomics | Internal | - | 1C+1H | TWAP 數學錯誤 ⭐NEW |
| zaros-2025 | Perp DEX | CodeHawks | - | H+M | 權重分配錯誤 |
| raac-2025 | NFT Lending | CodeHawks | $77K | H+M | Oracle staleness |
| revert-lend-2024 | Lending | Code4rena | $45K | 6H+27M | Permit2, Reentrancy |
| wise-lending-2024 | Lending | Code4rena | $60K | 5H+17M | receive() guard reset |
| size-2024 | Credit Market | Code4rena | $50K | 4H+13M | Swap fee calculation |
| sentiment-v2-2024 | Lending | Sherlock | $47.5K | H+M | Multi-collateral issues |
| decent-2024 | Bridge | Code4rena | $36.5K | 4H+5M | setRouter no access control |
| thorchain-2024 | Bridge/DEX | Code4rena | $36.5K | 2H+2M | Rebasing token, transferOut |
| eigenlayer-2024 | Restaking | Trail of Bits | - | H+M | Withdrawal delay bypass ⭐NEW |
| uniswapx-2024 | Intent/Solver | OpenZeppelin | - | H+M | Cross-chain order replay ⭐NEW |
| erc4337-aa-2024 | Account Abstraction | Various | - | H+2M | Paymaster drain ⭐NEW |

---

## 按協議類型分類

### Lending Protocol
```
推薦順序（按學習價值）:
1. revert-lend-2024 ⭐ (最多 findings，Uniswap V3 Position)
2. wise-lending-2024 (獨特的 reentrancy 模式)
3. size-2024 (P2P lending 特有問題)
4. sentiment-v2-2024 (multi-collateral)
```

### Cross-Chain Bridge
```
1. decent-2024 ⭐ (LayerZero 整合問題)
2. thorchain-2024 (multi-chain DEX)
```

### Perp DEX
```
1. zaros-2025 ⭐ (業務邏輯錯誤範例)
```

### NFT Lending
```
1. raac-2025 (Oracle + RWA)
```

### Staking / Restaking
```
1. eigenlayer-2024 ⭐ (Withdrawal delay bypass, slashing propagation) ⭐NEW
```

### Intent / Solver
```
1. uniswapx-2024 ⭐ (Cross-chain order replay, Dutch auction timing) ⭐NEW
```

### Account Abstraction (ERC-4337)
```
1. erc4337-aa-2024 ⭐ (Paymaster drain, cross-chain UserOp replay) ⭐NEW
```

---

## 詳細案例

### Zaros 2025 (Perp DEX) ✅ Complete
**路徑:** [zaros/zaros-perpetuals.md](zaros/zaros-perpetuals.md)

**關鍵發現:**
- **C-01: Weight Distribution Bug** - 每個 market 的 `weight` 設成相同值，`totalWeight = weight` 而非 `N * weight`，導致所有 market 認為自己有 100% credit delegation
- 比較運算符反轉：`.lt()` vs `.gt()`（未確認）

**學習重點:**
- 業務邏輯錯誤比技術漏洞更難發現
- 用數字舉例驗證邏輯的重要性
- Loop 中設值時要特別注意是否每個 iteration 都該設相同值

**代碼位置:** `src/market-making/leaves/Vault.sol` L508-533

---

### Revert Lend 2024 (Lending) ⭐
**路徑:** [revert-lend-2024/](revert-lend-2024/)

**關鍵發現:**
- H-01: Permit2 未驗證 token 地址
- H-02: onERC721Received 重入
- H-03: transform() 未驗證 calldata 中的 tokenId
- H-04: V3Utils.execute() 無權限控制
- H-05: TWAP 負數 tick 計算錯誤
- H-06: 惡意 onERC721Received 阻止清算

**學習重點:**
- Uniswap V3 Position 作為抵押品的特殊風險
- ERC721 callback 的多種攻擊向量

---

### Wise Lending 2024 (Lending)
**路徑:** [wise-lending-2024/](wise-lending-2024/)

**關鍵發現:**
- H-01: receive() 重置 reentrancy guard
- H-02: 用戶可免費消除債務

**學習重點:**
- Reentrancy guard 的非預期重置路徑
- 複雜合約中的邊界條件

---

### Decent 2024 (Bridge) ⭐
**路徑:** [decent-2024/](decent-2024/)

**關鍵發現:**
- H-01: setRouter() 無權限控制 → 整個 TVL 可被盜
- H-02: Gas 不足導致 LayerZero channel 阻塞
- H-03: refund 地址編碼錯誤
- H-04: WETH 不足時的回退邏輯錯誤

**學習重點:**
- 跨鏈橋的特有風險模式
- LayerZero 整合的常見錯誤

---

### THORChain 2024 (Bridge/DEX)
**路徑:** [thorchain-2024/](thorchain-2024/)

**關鍵發現:**
- H-01: Rebasing token (AMPL) 可盜取資金
- H-02: transferOut 缺少授權檢查

**學習重點:**
- 特殊 token 類型的處理
- Multi-chain 環境的複雜性

---

## 使用方式

### Pass 4 時載入
```
根據 Pass 1 識別的協議類型，載入相關案例：

Lending → 載入 revert-lend, wise-lending, size, sentiment-v2
Bridge → 載入 decent, thorchain
Perp DEX → 載入 zaros
NFT → 載入 raac
```

### 問題模板
```
對比這份代碼與 {案例名} 的相似之處：
1. 是否有類似的架構模式？
2. 歷史漏洞在這裡是否可能重現？
3. 他們的修復方案是否被採用？
```

---

### EigenLayer 2024 (Restaking) ⭐NEW
**路徑:** [eigenlayer-2024/](eigenlayer-2024/)

**關鍵發現:**
- H-01: Withdrawal delay bypass via operator change
- M-01: Slashing propagation precision loss

**學習重點:**
- Withdrawal delay 的 binding point 是核心安全屬性
- Operator 切換需要 cooldown

---

### UniswapX 2024 (Intent/Solver) ⭐NEW
**路徑:** [uniswapx-2024/](uniswapx-2024/)

**關鍵發現:**
- H-01: Cross-chain order replay (EIP-712 domain separator 不夠)
- M-01: Exclusive filler front-running decay start

**學習重點:**
- Intent order 需 order-level chain binding
- Dutch auction timing 與 block inclusion 的 MEV 交互

---

### ERC-4337 AA 2024 (Account Abstraction) ⭐NEW
**路徑:** [erc4337-aa-2024/](erc4337-aa-2024/)

**關鍵發現:**
- H-01: Paymaster drain via gas griefing
- M-01: Cross-chain UserOp replay
- M-02: initCode front-running

**學習重點:**
- Paymaster 是 4337 最大攻擊面
- CREATE2 same-address 是跨鏈 replay 的系統性風險
