# Weird ERC20 Token Integration Vulnerabilities

> **影響範圍:** 所有接受外部 ERC20 token 的 DeFi 協議（DEX, Lending, Vault, Bridge 等）
> **實戰重要性:** ⭐⭐⭐⭐⭐ — 幾乎每個審計都會遇到 token 整合問題
> **參考:** [d-xo/weird-erc20](https://github.com/d-xo/weird-erc20), [Trail of Bits Token Checklist](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/token_integration.md)

---

## 1. Fee-on-Transfer Tokens

**受影響 Token:** STA, PAXG, USDT (可啟用), USDC (可啟用)
**真實案例:** Balancer STA 池 $500K 被抽乾 (2020)

### 漏洞模式
協議假設 `transferFrom(from, to, amount)` 後接收方收到 `amount`，但實際收到的少於 `amount`。

```solidity
// ❌ 漏洞代碼
function deposit(IERC20 token, uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // 記錄的比實際收到的多！
}

function withdraw(IERC20 token, uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount);  // 協議虧損
}
```

```solidity
// ✅ 安全代碼 — 使用前後餘額差
function deposit(IERC20 token, uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;
    balances[msg.sender] += received;  // 記錄實際收到的
}
```

### 檢測要點
- 搜尋所有 `transferFrom` 後直接使用 `amount` 而非檢查餘額差的位置
- 特別注意 `totalAssets`, `deposit`, `mint` 等核心會計函數
- Fee 可能動態變化（USDT/USDC 目前 fee=0 但可被啟用）

---

## 2. Rebasing Tokens

**受影響 Token:** AMPL, stETH (Lido), aTokens (AAVE), OHM (Olympus)
**機制:** 餘額在 transfer 之外自動變化（膨脹或收縮）

### 漏洞模式
協議快取 token 餘額（如 Uniswap V2/Balancer），rebasing 後快取值過時。

```solidity
// ❌ 漏洞代碼 — 快取餘額
contract Pool {
    uint256 public reserve0;  // 快取的餘額
    uint256 public reserve1;
    
    function swap(uint256 amountIn, uint256 amountOut) external {
        // reserve0 可能已因 rebase 而變化，但此處未更新
        require(amountIn * reserve1 >= amountOut * reserve0);
        // ... 實際 token 餘額已變化但 reserve 未同步
    }
}
```

```solidity
// ✅ 安全代碼 — 使用 wrapped version 或即時查詢
// 方案 1: 使用 wstETH 而非 stETH (wrapped non-rebasing version)
// 方案 2: 同步機制
function sync() external {
    reserve0 = token0.balanceOf(address(this));
    reserve1 = token1.balanceOf(address(this));
}

function swap(uint256 amountIn, uint256 amountOut) external {
    sync();  // 每次操作前同步
    // ...
}
```

### 攻擊場景
1. **正向 rebase 套利:** 在 rebase 前存入，rebase 後提取（獲得膨脹收益但協議未計入）
2. **負向 rebase 損失:** 協議記錄的餘額 > 實際餘額，後來的提款者無法提取
3. **三明治 rebase:** 在 rebase 交易前後夾擊

### 檢測要點
- 協議是否快取 token 餘額？(`reserve`, `totalDeposited`, `lastBalance`)
- 是否支援 rebasing tokens？如果支援，同步機制是否正確？
- 份額計算是否基於快取值？

---

## 3. Missing Return Values

**受影響 Token:** USDT, BNB, OMG, Tether Gold (返回 false 即使成功)
**真實案例:** BNB 被卡在 Uniswap V1 中

### 漏洞模式
```solidity
// ❌ 漏洞代碼 — USDT 的 transfer 不返回 bool
function doTransfer(IERC20 token, address to, uint256 amount) internal {
    bool success = token.transfer(to, amount);  // USDT: 編譯錯誤或靜默失敗
    require(success);  // 永遠不會到達
}
```

```solidity
// ✅ 安全代碼 — 使用 SafeERC20
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

using SafeERC20 for IERC20;

function doTransfer(IERC20 token, address to, uint256 amount) internal {
    token.safeTransfer(to, amount);  // 處理所有 return value 情況
}
```

### Tether Gold 特殊情況
Tether Gold 宣告返回 bool 但即使成功也返回 false — 即使用 SafeERC20 也無法正確處理。

### 檢測要點
- 搜尋所有 `token.transfer()` / `token.transferFrom()` / `token.approve()` 調用
- 是否使用 SafeERC20 或等效的安全封裝？
- 是否有 `require(token.transfer(...))` 模式？

---

## 4. Tokens with Blocklists / Blacklists

**受影響 Token:** USDC, USDT, BUSD, TUSD
**機制:** 合約級別的地址黑名單，被封鎖地址無法轉入轉出

### 漏洞模式

```solidity
// ❌ 漏洞場景 — 用戶資金被鎖定
contract Vault {
    function withdraw(uint256 shares) external {
        uint256 assets = convertToAssets(shares);
        _burn(msg.sender, shares);
        // 如果 msg.sender 被 USDC 黑名單，此處 revert
        // 但 shares 已被燒毀 → 用戶永久損失
        USDC.transfer(msg.sender, assets);  // ← revert!
    }
}
```

```solidity
// ✅ 安全代碼 — 允許指定接收地址
function withdraw(uint256 shares, address receiver) external {
    uint256 assets = convertToAssets(shares);
    _burn(msg.sender, shares);
    USDC.transfer(receiver, assets);  // 用戶可指定未被封鎖的地址
}
```

### 攻擊場景
1. **資金鎖定:** 合約地址被加入黑名單 → 所有用戶資金被困
2. **勒索攻擊:** 威脅將合約加入黑名單
3. **清算失敗:** 借貸協議中，被黑名單的借款人無法被清算
4. **LP 鎖定:** AMM 中某個 LP 被黑名單 → 無法移除流動性

### 檢測要點
- 是否有 `withdraw(receiver)` 模式允許指定替代接收地址？
- transfer 失敗是否會導致狀態不一致？（如先改變狀態再 transfer）
- 清算路徑是否會因 blocklist 而失敗？

---

## 5. Low/High Decimal Tokens

**受影響 Token:** USDC/USDT (6), GUSD (2), WBTC (8), YAM-V2 (24)

### 漏洞模式 — Low Decimals

```solidity
// ❌ 漏洞代碼 — 假設 18 decimals
function convertToShares(uint256 assets) public view returns (uint256) {
    return assets * totalSupply / totalAssets;
    // GUSD (2 decimals): 1 GUSD = 100 units
    // 如果 totalAssets 很小，整數除法導致嚴重精度損失
}
```

```solidity
// ✅ 安全代碼 — 使用 decimal offset
uint256 private immutable _decimalsOffset;

constructor(IERC20 asset) {
    _decimalsOffset = 10 ** (18 - asset.decimals());
}

function convertToShares(uint256 assets) public view returns (uint256) {
    return assets * _decimalsOffset * totalSupply / (totalAssets * _decimalsOffset);
}
```

### 漏洞模式 — High Decimals

```solidity
// ❌ 漏洞代碼 — overflow
function calculateValue(uint256 amount, uint256 price) internal pure returns (uint256) {
    return amount * price / 1e18;  // YAM-V2 (24 decimals): amount 可能非常大
    // amount * price 可能 overflow
}
```

### 精度攻擊（First Depositor Attack 變體）
```solidity
// 攻擊流程 (USDC, 6 decimals):
// 1. 攻擊者存入 1 wei USDC → 獲得 1 share
// 2. 攻擊者直接轉入 1_000_000 USDC (1M units) 到 vault
// 3. totalAssets = 1_000_001, totalShares = 1
// 4. 受害者存入 999_999 USDC → shares = 999_999 * 1 / 1_000_001 = 0
// 5. 攻擊者提取 1 share → 獲得所有資產
// Low decimals 使此攻擊更便宜
```

### 檢測要點
- 是否硬編碼 `1e18` 或假設 18 decimals？
- 乘法是否可能 overflow（high decimal tokens）？
- Vault/Pool 是否有 first depositor 保護（virtual shares/assets）？
- 混合不同 decimal 的 token 時精度處理是否正確？

---

## 6. Pausable Tokens

**受影響 Token:** BNB, ZIL, WBTC (部分), 多數中心化穩定幣

### 漏洞模式
```solidity
// ❌ 漏洞場景 — 暫停導致協議功能中斷
contract LendingPool {
    function liquidate(address borrower) external {
        // 如果抵押品 token 被暫停 → 清算失敗
        collateralToken.transfer(msg.sender, reward);  // ← revert if paused!
        // 壞帳無法清算 → 協議損失
    }
}
```

### 檢測要點
- 關鍵路徑（清算、提款）是否會因 token 暫停而失敗？
- 是否有 fallback 機制處理 token 暫停？
- 時間敏感操作（清算、期限到期）是否受 pause 影響？

---

## 7. Approval Race Condition Tokens

**受影響 Token:** USDT, KNC
**機制:** 不允許從非零值直接修改 approve 為另一個非零值

### 漏洞模式
```solidity
// ❌ 漏洞代碼 — USDT 的 approve 會 revert
function setAllowance(IERC20 token, address spender, uint256 amount) internal {
    token.approve(spender, amount);  // 如果現有 allowance > 0 且 amount > 0 → revert
}
```

```solidity
// ✅ 安全代碼 — 先歸零再設定
function setAllowance(IERC20 token, address spender, uint256 amount) internal {
    token.safeApprove(spender, 0);
    token.safeApprove(spender, amount);
}

// 更好: 使用 forceApprove (OpenZeppelin 5.x)
function setAllowance(IERC20 token, address spender, uint256 amount) internal {
    token.forceApprove(spender, amount);
}
```

### 檢測要點
- 搜尋所有 `approve` 調用
- 是否先歸零再設定？或使用 `forceApprove`？
- Router/Zap 合約中批量操作是否正確處理 approval？

---

## 8. Flash Mintable Tokens

**受影響 Token:** DAI (Flash Mint Module), ERC-3156 tokens
**機制:** 可在單筆交易中鑄造任意數量的 token（只要在交易結束前歸還）

### 漏洞模式
```solidity
// ❌ 漏洞代碼 — 使用 totalSupply 作為價格基準
function getPrice() public view returns (uint256) {
    return reserveETH * 1e18 / token.totalSupply();
    // Flash mint 可將 totalSupply 膨脹到 type(uint256).max
    // → price 趨近於 0
}
```

### 攻擊場景
1. Flash mint 大量 token → totalSupply 暴增
2. 依賴 totalSupply 的計算被操控
3. 在同一交易中利用被操控的價格
4. 歸還 flash minted tokens

### 檢測要點
- 是否使用 `totalSupply()` 作為計算依據？
- 是否假設 `totalSupply` 是穩定/有限的？
- 治理投票中的 token 權重是否可被 flash mint 操控？

---

## 9. Multiple Token Addresses (Double Entry Point)

**受影響 Token:** 部分 proxy token（如舊版 SNX/sUSD 有雙入口）
**真實案例:** Compound cTUSD 漏洞 — $12.3M 風險 (caught by Immunefi)

### 漏洞模式
```solidity
// ❌ 漏洞代碼 — 假設每個 token 只有一個地址
mapping(address => bool) public isPoolToken;

constructor(address tokenA, address tokenB) {
    isPoolToken[tokenA] = true;
    isPoolToken[tokenB] = true;
}

function rescueFunds(address token, uint256 amount) external onlyOwner {
    require(!isPoolToken[token], "cannot rescue pool tokens");
    // 如果 tokenA 有第二個地址 tokenA_proxy，owner 可以用 tokenA_proxy 繞過檢查
    IERC20(token).transfer(msg.sender, amount);
}
```

### 檢測要點
- token 地址比較是否考慮了 proxy/多入口情況？
- `rescueFunds` 類函數是否可被繞過？
- 是否在 token 白名單中同時註冊了所有入口？

---

## 10. ERC-777 Hook Reentrancy

**受影響 Token:** imBTC, 所有 ERC-777 compatible tokens
**真實案例:** imBTC/Uniswap V1 池被抽乾, lendf.me $25M 損失 (2020)

### 漏洞模式
ERC-777 在 transfer 前後會調用 `tokensToSend` / `tokensReceived` hooks，即使接口看起來是普通 ERC-20。

```solidity
// ❌ 漏洞代碼 — 不知道 token 有 hooks
function swap(uint256 amountIn) external {
    token.transferFrom(msg.sender, address(this), amountIn);
    // ← ERC-777: 此處觸發 msg.sender 的 tokensToSend hook
    // ← 攻擊者在 hook 中重入 swap()
    
    uint256 amountOut = calculateOutput(amountIn);
    otherToken.transfer(msg.sender, amountOut);
}
```

```solidity
// ✅ 安全代碼 — Checks-Effects-Interactions + reentrancy guard
function swap(uint256 amountIn) external nonReentrant {
    uint256 amountOut = calculateOutput(amountIn);
    // Effects first
    _updateReserves(amountIn, amountOut);
    // Interactions last
    token.transferFrom(msg.sender, address(this), amountIn);
    otherToken.transfer(msg.sender, amountOut);
}
```

### 檢測要點
- 是否有 reentrancy guard 在所有外部 token 交互函數上？
- 是否遵循 Checks-Effects-Interactions 模式？
- 即使聲稱不支援 ERC-777，是否有防護？（防禦性程式設計）

---

## 11. Revert on Zero Value Transfers

**受影響 Token:** LEND, 部分 deflationary tokens

### 漏洞模式
```solidity
// ❌ 漏洞代碼 — 未檢查零值
function claimRewards(address user) external {
    uint256 reward = pendingRewards[user];
    pendingRewards[user] = 0;
    rewardToken.transfer(user, reward);  // reward = 0 時 revert!
}
```

```solidity
// ✅ 安全代碼
function claimRewards(address user) external {
    uint256 reward = pendingRewards[user];
    if (reward > 0) {
        pendingRewards[user] = 0;
        rewardToken.transfer(user, reward);
    }
}
```

### 檢測要點
- 是否有 `transfer(0)` 的可能路徑？
- 批量操作中某些用戶獎勵為 0 是否會導致整個交易 revert？

---

## 12. Revert on Large Values (uint96 Tokens)

**受影響 Token:** UNI, COMP
**機制:** 內部使用 uint96 存儲餘額，approve/transfer 超過 uint96.max 會 revert

### 漏洞模式
```solidity
// ❌ 漏洞代碼 — 使用 type(uint256).max 做 approval
token.approve(spender, type(uint256).max);
// UNI/COMP: 特殊邏輯 — uint256.max 設定為 uint96.max 而非 revert
// 但 approve(spender, uint96.max + 1) 會 revert
```

### 檢測要點
- 是否有使用大數值（> uint96.max）做 approve 或 transfer？
- 是否假設 `type(uint256).max` approval 等同於「無限」？

---

## 13. Upgradeable Tokens

**受影響 Token:** USDC, USDT, TUSD
**機制:** Token 邏輯可被管理員升級，語義可能改變

### 漏洞模式
- Token 升級後添加 fee-on-transfer → 破壞原有會計邏輯
- Token 升級後添加 blocklist → 合約可能被封鎖
- Token 升級後改變 decimals → 精度計算全部錯誤

### 檢測要點
- 協議是否考慮了底層 token 升級的可能性？
- 是否有「熔斷」機制在偵測到 token 行為變化時暫停？
- 是否監控 token 的 proxy 升級事件？

---

## 14. Non-Standard Permit (EIP-2612 變體)

**受影響 Token:** DAI, RAI, GLM, STAKE, CHAI (使用 DAI-style permit)
**機制:** permit 函數簽名與 EIP-2612 不同

### 漏洞模式
```solidity
// EIP-2612 標準:
function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)

// DAI-style:
function permit(address holder, address spender, uint256 nonce, uint256 expiry, bool allowed, uint8 v, bytes32 r, bytes32 s)
// 注意: DAI permit 沒有 value 參數 — 只有 allowed (true/false)
```

```solidity
// ❌ 漏洞代碼 — 假設所有 token 都遵循 EIP-2612
function depositWithPermit(address token, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s);
    // DAI: 此調用會失敗（參數不匹配）
    IERC20(token).transferFrom(msg.sender, address(this), amount);
}
```

### 檢測要點
- permit 調用是否用 try-catch 包裹？（推薦模式）
- 是否針對 DAI-style permit 有特殊處理？
- permit 失敗是否會導致整個交易失敗？

---

## 15. Tokens with Transfer Hooks (ERC-1363, ERC-4524)

**機制:** 類似 ERC-777 但基於 ERC-20 擴展，transfer 後自動調用接收者的 callback

### 檢測要點
- 與 ERC-777 相同的 reentrancy 風險
- `transferAndCall` / `approveAndCall` 是否被考慮？

---

## 真實案例彙總

| 事件 | Token 類型 | 損失 | 年份 | 漏洞類別 |
|------|-----------|------|------|----------|
| Balancer STA 池 | Fee-on-Transfer | $500K | 2020 | #1 |
| imBTC/Uniswap V1 | ERC-777 Reentrancy | ~$300K | 2020 | #10 |
| lendf.me | ERC-777 Reentrancy | $25M | 2020 | #10 |
| BNB/Uniswap V1 | Missing Return Value | 資金卡住 | 2018 | #3 |
| Compound cTUSD | Double Entry Point | $12.3M 風險 | 2022 | #9 |
| Harvest Finance | Rebasing/Price | $34M | 2020 | #2 |
| Beanstalk | Flash Mint (Governance) | $182M | 2022 | #8 |
| EtherDelta | Code Injection via Name | 數千美元 | 2017 | N/A |

---

## 審計清單

### A. Transfer 安全
- [ ] 所有 token transfer 是否使用 SafeERC20？
- [ ] 是否使用前後餘額差計算實際接收量？（fee-on-transfer）
- [ ] transfer(0) 是否被正確處理？
- [ ] transfer 失敗是否導致狀態不一致？

### B. 餘額與精度
- [ ] 是否硬編碼 18 decimals？
- [ ] 混合不同 decimal 的 token 精度計算是否正確？
- [ ] 是否有 first depositor 攻擊防護？
- [ ] 餘額快取是否考慮 rebasing？

### C. Approval 安全
- [ ] approve 是否先歸零再設定？
- [ ] permit 是否用 try-catch 包裹？
- [ ] 是否考慮 DAI-style permit？
- [ ] 是否有 approval race condition 風險？

### D. 特殊行為防護
- [ ] reentrancy guard 是否覆蓋所有 token 交互？
- [ ] blocklist token 是否有替代接收地址機制？
- [ ] pausable token 是否影響關鍵路徑（清算、提款）？
- [ ] 是否考慮 token 升級後行為變化？

### E. Token 假設驗證
- [ ] 是否假設 totalSupply 是穩定的？（flash mint）
- [ ] 是否假設每個 token 只有一個地址？（double entry）
- [ ] 是否假設 transfer 不會調用外部代碼？（hooks）
- [ ] 是否假設 uint256 足夠？（uint96 tokens）

### F. 防禦性程式設計
- [ ] 是否有 token 白名單或封裝層？
- [ ] 是否有行為變化偵測/熔斷機制？
- [ ] 文件是否明確列出支援的 token 類型和限制？

---

*基於 d-xo/weird-erc20、Trail of Bits token checklist、真實攻擊案例整理*
*建立日期: 2026-02-14*
