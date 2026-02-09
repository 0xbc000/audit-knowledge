# Stablecoin & CDP Protocol Vulnerability Patterns

> 穩定幣與 CDP（Collateralized Debt Position）協議的漏洞模式
> 基於真實案例分析：Abracadabra ($21M+ across 3 exploits), Prisma Finance ($12.3M), Terra/UST (death spiral), Bonq ($100M+)

---

## 1. Batch Action / cook() State Reset Attacks

### 描述
CDP 協議常提供 `cook()` 或 `multicall()` 函數讓用戶在單一交易中批次執行多個操作。若批次操作之間的狀態管理不當，攻擊者可利用操作順序繞過安全檢查。

### 真實案例：Abracadabra Third Exploit ($1.8M, Oct 2025)

**攻擊流程：**
```
1. 調用 cook([ACTION_BORROW, ACTION_0])
2. ACTION_BORROW (ID=5): 借出 MIM，設置 needsSolvencyCheck = true
3. ACTION_0 (未定義): 觸發 _additionalCookAction fallback
4. Fallback 返回默認 CookStatus{false, false}
5. needsSolvencyCheck 被重置為 false
6. 跳過償付能力檢查 → 超額借款成功
```

**漏洞代碼模式：**
```solidity
// VULNERABLE: cook() 中的 else branch 重置了關鍵狀態
function cook(uint8[] calldata actions, ...) external {
    CookStatus memory status;
    for (uint i = 0; i < actions.length; i++) {
        if (actions[i] == ACTION_BORROW) {
            // 借款邏輯...
            status.needsSolvencyCheck = true;
        } else if (actions[i] == ACTION_REPAY) {
            // 還款邏輯...
        } else {
            // ❌ BUG: 返回默認 status，覆蓋了之前設置的 flag
            status = _additionalCookAction(actions[i], ...);
        }
    }
    if (status.needsSolvencyCheck) {
        require(_isSolvent(msg.sender), "not solvent");
    }
}
```

**修復方式：**
```solidity
// FIXED: 保留已設置的 flag
} else {
    CookStatus memory additionalStatus = _additionalCookAction(actions[i], ...);
    status.needsSolvencyCheck = status.needsSolvencyCheck || additionalStatus.needsSolvencyCheck;
}
```

### 檢測要點
- [ ] `cook()`/`multicall()` 是否在所有分支中正確傳播安全 flag？
- [ ] 未知/預留的 action ID 是否會觸發默認行為而重置狀態？
- [ ] 批次操作的順序是否會影響最終安全檢查？
- [ ] `else`/`default` 分支是否 revert 或保留現有狀態？

---

## 2. Ghost Collateral / Phantom Position Attacks

### 描述
當 CDP 協議與外部協議（如 GMX、Aave）整合時，存款/提取可能是異步的。攻擊者可利用「幻影抵押品」——即已記錄但尚未實際到賬的資產——來借款。

### 真實案例：Abracadabra GMX V2 Exploit ($13M, Mar 2025)

**攻擊流程：**
```
1. 創建 GMX V2 market deposit order（異步）
2. Cauldron 記錄抵押品增加（基於 order 而非實際餘額）
3. 攻擊者基於「幻影抵押品」借出 MIM
4. GMX deposit order 失敗/被取消
5. 抵押品從未真正到賬，但 MIM 已被借走
```

**漏洞模式：**
```solidity
// VULNERABLE: 基於訂單而非實際餘額計算抵押品
function _getCollateralValue(address user) internal view returns (uint256) {
    uint256 actualBalance = collateralToken.balanceOf(address(this));
    uint256 pendingDeposits = _getPendingDeposits(user);
    // ❌ BUG: pending deposits 可能永遠不會到賬
    return actualBalance + pendingDeposits;
}
```

### 檢測要點
- [ ] 抵押品計算是否包含尚未完成的異步操作？
- [ ] 外部協議的 deposit/withdrawal 失敗時，CDP 狀態是否正確回滾？
- [ ] 是否存在「樂觀記賬」（先記錄再確認）的模式？
- [ ] callback 函數失敗時的回退邏輯是否正確？

---

## 3. Migration/Zap Contract Delegation Exploits

### 描述
CDP 協議升級時常提供 migration 合約，用戶需授權該合約操作其頭寸。若 migration 合約缺少輸入驗證，已授權的用戶資金可被竊取。

### 真實案例：Prisma Finance ($12.3M, Mar 2024)

**攻擊流程：**
```
1. 用戶已調用 setDelegateApproval(MigrateTroveZap, true)
2. 攻擊者直接調用 mkUSD.flashLoan()，receiver 設為 MigrateTroveZap
3. onFlashLoan() 無驗證地執行「遷移」操作
4. 關閉受害者的 trove，以更少抵押品重新開啟
5. 攻擊者提取差額
```

**漏洞模式：**
```solidity
// VULNERABLE: onFlashLoan 信任所有傳入的 data
function onFlashLoan(
    address initiator,     // ❌ 未驗證 initiator
    address token,
    uint256 amount,
    uint256 fee,
    bytes calldata data
) external returns (bytes32) {
    // ❌ BUG: data 可由任何 flashloan 調用者控制
    (address owner, uint256 newCollateral, ...) = abi.decode(data, ...);
    troveManager.closeTrove(owner);  // 使用受害者的 delegation
    troveManager.openTrove(owner, newCollateral, ...);
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

**修復方式：**
```solidity
// FIXED: 驗證 initiator 和 caller
function onFlashLoan(...) external returns (bytes32) {
    require(msg.sender == address(debtToken), "invalid caller");
    require(initiator == address(this), "invalid initiator");  // ✅ 只接受自己發起的 flashloan
    // ...
}
```

### 檢測要點
- [ ] flashloan callback 是否驗證 `initiator` 和 `msg.sender`？
- [ ] delegation/approval 的範圍是否過大？
- [ ] migration 合約是否可被第三方直接觸發？
- [ ] 「一次性」migration 合約是否在使用後禁用？

---

## 4. Debt Token Rounding & Precision Attacks

### 描述
CDP 協議中 debt token 的鑄造/燒毀計算若存在精度問題，可被利用進行微額操控或無限鑄造。

### 真實案例：Abracadabra First Exploit ($6.5M, Jan 2024)

**攻擊模式：**
```
利率累積使 debt share 與 actual debt 產生差異
→ 精度下溢使某些操作可以 borrow 而不增加 debt shares
→ 或 repay 少量卻獲得大量 collateral
```

### 常見漏洞模式

#### 4a. Share/Amount 轉換精度攻擊
```solidity
// VULNERABLE: 向下取整允許免費借款
function debtShareToAmount(uint256 shares) public view returns (uint256) {
    return shares * totalDebt / totalShares;  // ❌ 向下取整
}

function amountToDebtShare(uint256 amount) public view returns (uint256) {
    return amount * totalShares / totalDebt;  // ❌ 向下取整
}

// 攻擊: 當 totalDebt >> totalShares 時
// debtShareToAmount(1) 可能 = 0，免費借款
```

#### 4b. 利率累積間隙
```solidity
// VULNERABLE: accrue 和 borrow 之間的 timing
function borrow(uint256 amount) external {
    accrue();  // 更新利率
    // ... 在 accrue 之後、更新 totalDebt 之前
    // 用戶可能利用舊的 share 比率
    uint256 shares = amountToDebtShare(amount);
    userDebtShares[msg.sender] += shares;
    totalShares += shares;
    totalDebt += amount;  // ❌ 利率已改變但轉換比率基於舊值
}
```

### 檢測要點
- [ ] debt share ↔ amount 轉換是否在正確方向取整？（借款向上，還款向下）
- [ ] 利率累積是否在所有讀取 debt 的操作前執行？
- [ ] 首個借款者是否有特殊處理防止比率操控？
- [ ] 微額借款（dust amounts）是否被正確處理或禁止？

---

## 5. Oracle Manipulation for CDP Protocols

### 描述
CDP 協議特別依賴 oracle 來判斷抵押品價值、清算閾值和贖回價格。Oracle 操控可導致：不當清算、超額借款、或阻止必要的清算。

### 真實案例：Bonq Protocol ($100M+, Feb 2023)

**攻擊流程：**
```
1. Bonq 使用 Tellor Oracle（任何人可提交價格）
2. 攻擊者提交極高的 ALBT 價格
3. 基於虛高價格借出大量 BEUR 穩定幣
4. 攻擊者提交極低的 ALBT 價格
5. 清算其他用戶的健康頭寸
6. 獲利 ~$100M
```

### CDP 特有的 Oracle 風險

#### 5a. 穩定幣自身價格的 Oracle
```solidity
// RISKY: 穩定幣的贖回/清算使用自身市場價格
function getRedemptionPrice() external view returns (uint256) {
    // ❌ 如果穩定幣脫錨，贖回邏輯可能失效
    return oracle.getPrice(address(stablecoin));
}

// BETTER: 使用硬編碼 $1 或有界限的價格
function getRedemptionPrice() external view returns (uint256) {
    uint256 marketPrice = oracle.getPrice(address(stablecoin));
    return Math.min(marketPrice, 1e18);  // ✅ 上限 $1
}
```

#### 5b. 多抵押品 Oracle 不一致
```solidity
// VULNERABLE: 不同抵押品使用不同 oracle 延遲
// ETH: Chainlink (heartbeat 1h)
// stETH: 自定義 oracle (可即時更新)
// 攻擊: stETH 價格更新但 ETH 尚未更新時套利
```

#### 5c. Yield-Bearing Token 作為抵押品
```solidity
// VULNERABLE: 使用 exchange rate 而非實際市場價
function getCollateralValue(uint256 amount) external view returns (uint256) {
    // ❌ stETH/ETH exchange rate 可被操控
    uint256 ethAmount = stETH.getPooledEthByShares(amount);
    return ethAmount * ethPrice;
}
```

### 檢測要點
- [ ] Oracle 提交者是否需要質押或有延遲？
- [ ] 是否檢查 oracle staleness（過期數據）？
- [ ] 多抵押品場景中 oracle 更新時間是否一致？
- [ ] yield-bearing token 是否使用 TWAP 而非即時 exchange rate？

---

## 6. Stability Pool & Liquidation Gaming

### 描述
CDP 協議（如 Liquity）使用穩定池來處理清算。穩定池的存取、清算觸發和獎勵分配中存在多種博弈機會。

### 漏洞模式

#### 6a. Just-In-Time Stability Pool Deposits
```
1. 監控 mempool 中的清算交易
2. 在清算前存入穩定池
3. 獲取清算抵押品折扣
4. 立即提取
```

#### 6b. 自我清算套利
```solidity
// 攻擊流程:
// 1. 開 CDP，抵押率剛好在清算線上
// 2. 操控 oracle 使 CDP 可被清算
// 3. 用自己的穩定幣清算自己
// 4. 獲取清算折扣（通常 5-10%）
```

#### 6c. 穩定池份額計算漏洞
```solidity
// VULNERABLE: 存款和清算事件的順序影響份額
function deposit(uint256 amount) external {
    // 如果在同一 block 中有清算事件
    // 存款者可能獲得/避免清算損失
    uint256 shares = amount * totalShares / totalDeposits;
    // ...
}
```

#### 6d. 贖回排序攻擊（Liquity 類型）
```
Liquity 的贖回按抵押率從低到高排序
攻擊者可以:
1. 調整自己 CDP 的抵押率到剛好不被贖回的位置
2. 大量贖回其他人的 CDP
3. 贖回後自己的 CDP 變成最低抵押率，被動獲利
```

### 檢測要點
- [ ] 穩定池存取是否有 cooldown 或 delay？
- [ ] 清算是否可以在同一 block 中與其他操作組合？
- [ ] 自我清算是否被禁止或限制？
- [ ] 贖回排序是否可被博弈？

---

## 7. Peg Maintenance Mechanism Failures

### 描述
穩定幣的掛鉤維護機制（贖回、利率調整、穩定費）若有漏洞，可導致死亡螺旋或掛鉤失敗。

### 漏洞模式

#### 7a. 贖回機制反身性（Reflexivity）
```
1. 穩定幣輕微脫錨 ($0.98)
2. 套利者贖回穩定幣換取抵押品
3. 贖回降低了 CDP 的抵押率
4. 低抵押率的 CDP 被清算
5. 清算拋售抵押品，進一步壓低抵押品價格
6. 更多 CDP 進入清算區 → 死亡螺旋
```

#### 7b. 利率調整延遲
```solidity
// VULNERABLE: 利率調整過慢無法應對急劇脫錨
function adjustBorrowRate() external {
    uint256 currentPeg = getStablecoinPrice();
    if (currentPeg < 0.99e18) {
        // ❌ 每次只調 0.5%，脫錨 10% 時需要 20 次調整
        borrowRate += 50; // 0.5%
    }
}
```

#### 7c. 協議控制的穩定幣 mint/burn 權限
```solidity
// CRITICAL: 誰能 mint 穩定幣？
// 如果 mint 權限被攻破，可以無限鑄造
mapping(address => bool) public minters;

function mint(address to, uint256 amount) external {
    require(minters[msg.sender], "not minter");
    // ❌ 如果 minter 角色被添加了惡意地址...
    _mint(to, amount);
}
```

### 檢測要點
- [ ] 贖回機制是否有速率限制防止級聯清算？
- [ ] 利率調整機制是否能快速響應急劇偏離？
- [ ] mint/burn 權限是否有完善的 access control？
- [ ] 是否有 circuit breaker（熔斷機制）防止死亡螺旋？

---

## 8. Multi-Collateral CDP Risks

### 描述
支持多種抵押品的 CDP 協議（如 MakerDAO）面臨抵押品之間的相關性風險和管理複雜性。

### 漏洞模式

#### 8a. 抵押品相關性風險
```
場景: CDP 同時接受 stETH 和 rETH
- stETH 和 rETH 都是 ETH 衍生品
- ETH 暴跌時兩者同時跌，diversification 失效
- 系統認為風險分散但實際高度相關
```

#### 8b. 新抵押品類型引入的攻擊面
```solidity
// 添加新抵押品時的常見失誤:
// 1. 忘記設定正確的清算比率
// 2. 使用不適合的 oracle
// 3. 未考慮該代幣的特殊行為 (rebase, fee-on-transfer, etc.)
// 4. 債務上限 (ceiling) 設置不當

function addCollateral(
    address token,
    address oracle,
    uint256 liquidationRatio,
    uint256 debtCeiling
) external onlyGovernance {
    // ❌ 缺少對 token 行為的驗證
    // rebase token 會導致抵押品自動增減
    // fee-on-transfer 會導致記錄的抵押品 > 實際抵押品
}
```

#### 8c. 跨 Vault 互動
```solidity
// VULNERABLE: 用 Vault A 的抵押品影響 Vault B 的狀態
// 如果兩個 vault 共享同一個 oracle 或穩定池
// 可能出現跨 vault 的套利或攻擊
```

### 檢測要點
- [ ] 多抵押品之間的相關性是否被考慮？
- [ ] 新抵押品添加是否有完整的審計清單？
- [ ] rebase/fee-on-transfer 代幣是否被正確處理？
- [ ] 跨 vault 互動是否存在套利機會？

---

## 9. Governance & Parameter Manipulation

### 描述
CDP 協議的治理參數（清算比率、穩定費、債務上限）變更可能被利用。

### 漏洞模式

#### 9a. 前置參數變更
```
1. 治理提案: 將 ETH 清算比率從 150% 調高到 175%
2. 攻擊者在提案執行前，開啟 150%-175% 之間的 CDP
3. 提案執行後，這些 CDP 立即可被清算
4. 攻擊者（也是清算者）獲取清算獎勵
```

#### 9b. 債務上限（Debt Ceiling）繞過
```solidity
// VULNERABLE: debt ceiling 檢查時機
function borrow(uint256 amount) external {
    accrue();  // 利率累積增加 totalDebt
    // ❌ 如果 accrue() 使 totalDebt 超過 ceiling
    // 新借款仍然通過（ceiling 檢查在 accrue 之後）
    require(totalDebt + amount <= debtCeiling, "ceiling reached");
    // ...
}
```

### 檢測要點
- [ ] 參數變更是否有 timelock 讓用戶調整頭寸？
- [ ] debt ceiling 是否考慮了利率累積？
- [ ] 治理攻擊（flash loan governance）是否被防禦？

---

## 10. Emergency / Pause Mechanism Vulnerabilities

### 描述
CDP 協議的緊急暫停機制可能被濫用或設計不當。

### 漏洞模式

#### 10a. 暫停不完整
```solidity
// VULNERABLE: 暫停了借款但沒暫停清算
function borrow(uint256 amount) external whenNotPaused {
    // ...
}

function liquidate(address user) external {  // ❌ 不受 pause 限制
    // 協議暫停期間，用戶無法補倉但可以被清算
}
```

#### 10b. 緊急提款竊取用戶資金
```solidity
// DANGEROUS: admin 可以提走所有資金
function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
    IERC20(token).transfer(owner(), amount);
    // ❌ 沒有 timelock，沒有限制
}
```

#### 10c. 恢復後的狀態不一致
```
暫停期間:
- Oracle 價格持續變化但未被讀取
- 利率未累積
- 清算未執行

恢復後:
- 突然累積大量利率
- 大量頭寸同時進入清算區
- 可能導致系統性風險
```

### 檢測要點
- [ ] pause 是否覆蓋所有必要操作（包括清算、贖回）？
- [ ] 暫停期間用戶是否仍能增加抵押品/還款？
- [ ] 恢復後是否有 grace period？
- [ ] emergency functions 是否有 timelock 和 multi-sig？

---

## 11. Synthetic/Delta-Neutral Stablecoin Risks

### 描述
新型穩定幣（如 Ethena USDe）使用 delta-neutral 策略而非純抵押品，引入獨特的攻擊面。

### Ethena USDe 風險模型
```
USDe = stETH 多頭 + ETH 永續合約空頭
收益來源 = staking yield + funding rate

風險因素:
1. Funding rate 長期為負 → USDe 收益變負
2. CEX 對手方風險 → 頭寸無法平倉
3. stETH/ETH 脫錨 → delta 不再中性
4. 大規模贖回 → 平倉滑點
```

### 漏洞模式

#### 11a. 贖回攻擊
```
1. 持有大量 USDe/sUSDe
2. 監控 funding rate 變為負值
3. 大規模贖回，迫使協議平倉空單
4. 平倉推高永續合約價格
5. 剩餘空單虧損 → NAV 下降 → 更多贖回 → 螺旋
```

#### 11b. Cooldown 繞過
```solidity
// sUSDe 有 cooldown period 防止擠兌
// 但 sUSDe 可能在二級市場以折價交易
// 攻擊者可以:
// 1. 在二級市場折價買入 sUSDe
// 2. 等待 cooldown
// 3. 以 $1 贖回 → 無風險套利
```

### 檢測要點
- [ ] delta-neutral 策略在極端行情下是否仍然有效？
- [ ] cooldown 機制是否真正防止了擠兌？
- [ ] 清算/贖回是否有滑點保護？
- [ ] 外部 CEX 頭寸的驗證機制是否可靠？

---

## 審計清單：Stablecoin/CDP Protocol

### A. 核心機制安全
- [ ] A1: mint/burn 權限是否最小化？
- [ ] A2: 抵押品價值計算是否使用安全的 oracle？
- [ ] A3: 清算機制是否有足夠的激勵且不可被博弈？
- [ ] A4: 贖回機制是否有速率限制？
- [ ] A5: 利率累積是否在所有操作前正確執行？

### B. 批次操作安全
- [ ] B1: cook()/multicall() 是否正確傳播安全 flag？
- [ ] B2: 未知 action ID 是否被拒絕而非忽略？
- [ ] B3: 批次操作中的狀態是否在每步後一致？
- [ ] B4: 是否可以通過操作排序繞過檢查？

### C. 外部整合安全
- [ ] C1: flashloan callback 是否驗證 initiator？
- [ ] C2: migration/zap 合約是否限制調用者？
- [ ] C3: 異步操作（如 GMX orders）的回退邏輯是否正確？
- [ ] C4: delegation/approval 範圍是否最小化？

### D. 經濟安全
- [ ] D1: 穩定幣脫錨時系統行為是否安全？
- [ ] D2: 多抵押品相關性是否被考慮？
- [ ] D3: 死亡螺旋是否有熔斷機制？
- [ ] D4: 自我清算是否被限制？

### E. 治理與升級安全
- [ ] E1: 參數變更是否有 timelock？
- [ ] E2: 緊急暫停是否覆蓋所有必要操作？
- [ ] E3: 恢復後是否有 grace period？
- [ ] E4: emergency withdraw 是否有限制？

### F. 精度與邊界
- [ ] F1: debt share 轉換是否在安全方向取整？
- [ ] F2: 首個存款者/借款者是否有特殊保護？
- [ ] F3: dust amounts 是否被正確處理？
- [ ] F4: 最大/最小借款額是否有合理限制？

---

## 案例研究索引

| 協議 | 損失 | 日期 | 類別 | 關鍵漏洞 |
|------|------|------|------|----------|
| Abracadabra (3rd) | $1.8M | Oct 2025 | Batch State Reset | cook() 中未知 action 重置 solvency flag |
| Abracadabra (2nd) | $13M | Mar 2025 | Ghost Collateral | GMX V2 異步 deposit 的幻影抵押品 |
| Abracadabra (1st) | $6.5M | Jan 2024 | Precision/Rounding | debt share 精度攻擊 |
| Prisma Finance | $12.3M | Mar 2024 | Delegation Exploit | MigrateTroveZap 缺少 initiator 驗證 |
| Bonq Protocol | $100M+ | Feb 2023 | Oracle Manipulation | Tellor oracle 價格操控 |
| Terra/UST | $40B+ | May 2022 | Death Spiral | 算法穩定幣反身性崩潰 |
| Cashio | $52M | Mar 2022 | Mint Validation | 未驗證 backing token 類型即 mint |
| Beanstalk | $182M | Apr 2022 | Flash Governance | Flash loan 治理攻擊 |

---

*文件建立: 2026-02-10 02:00 AM (Asia/Taipei)*
*來源: Three Sigma, Halborn, Olympix, CertiK 事後分析報告 + Hacken/Elliptic 安全研究*
