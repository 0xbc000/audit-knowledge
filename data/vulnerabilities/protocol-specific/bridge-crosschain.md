# Cross-Chain Bridge 漏洞模式

> 橋接協議是 Web3 損失最慘重的攻擊面，累計超過 $2.8B 被盜（佔 DeFi 總損失 ~40%）。
> 本文檔系統化整理橋接漏洞模式，涵蓋 lock-and-mint、burn-and-unlock、消息傳遞、驗證器安全等。

---

## 1. 消息驗證繞過（Message Validation Bypass）

### 描述
橋接的核心是跨鏈消息驗證。如果驗證邏輯有缺陷，攻擊者可以偽造跨鏈消息，在目標鏈上解鎖/鑄造未支撐的資產。

### 漏洞模式

#### 1.1 Trusted Root 初始化錯誤
```solidity
// ❌ 漏洞代碼 - Nomad Bridge ($190M)
// 升級時將 trusted root 初始化為 0x00
function initialize(bytes32 _committedRoot) public initializer {
    committedRoot = _committedRoot; // 設為 0x00
}

// process() 中的驗證
function process(bytes memory _message) public {
    bytes32 _messageHash = keccak256(_message);
    // confirmAt[0x00] 被設為 1，所以任何未經驗證的消息都通過！
    require(acceptableRoot(messages[_messageHash]), "not accepted");
    // ... 執行轉帳
}
```

```solidity
// ✅ 安全代碼
function initialize(bytes32 _committedRoot) public initializer {
    require(_committedRoot != bytes32(0), "zero root");
    committedRoot = _committedRoot;
    // 明確不設置 confirmAt[0x00]
}

function process(bytes memory _message) public {
    bytes32 _messageHash = keccak256(_message);
    bytes32 _root = messages[_messageHash];
    require(_root != bytes32(0), "unknown message");
    require(acceptableRoot(_root), "not accepted");
}
```

**檢測要點:**
- 初始化函數是否可能將關鍵 root/hash 設為零值
- `mapping` 中零值是否有特殊含義（Solidity mapping 默認值為 0）
- 升級後是否重新初始化了關鍵狀態變量

#### 1.2 簽名驗證不完整
```solidity
// ❌ 漏洞代碼 - Wormhole ($326M)
// Guardian 簽名驗證使用了已廢棄的 Solana sysvar
fn verify_signatures(
    ctx: Context<VerifySig>,
    guardian_set_index: u32,
    signatures: Vec<[u8; 66]>,
) -> Result<()> {
    // 使用 Secp256k1 指令驗證，但未檢查指令是否真的來自
    // Secp256k1Program，允許攻擊者注入偽造的驗證結果
    let secp_ix = sysvar::instructions::load_instruction_at(
        0, // 假設第一條指令是 secp256k1
        &ctx.accounts.instruction_sysvar
    )?;
    // 缺少: 驗證 secp_ix.program_id == secp256k1_program::id()
}
```

```solidity
// ✅ 安全代碼
fn verify_signatures(ctx: ...) -> Result<()> {
    let secp_ix = sysvar::instructions::load_instruction_at(
        0,
        &ctx.accounts.instruction_sysvar
    )?;
    // 明確驗證程序 ID
    require!(
        secp_ix.program_id == secp256k1_program::id(),
        ErrorCode::InvalidProgram
    );
    // 驗證簽名數量 >= threshold
    require!(
        valid_sigs >= guardian_set.quorum(),
        ErrorCode::InsufficientSignatures
    );
}
```

**檢測要點:**
- 簽名驗證是否檢查了正確的 program/precompile
- 是否驗證了足夠數量的簽名（quorum）
- ecrecover 返回 address(0) 時是否正確處理

#### 1.3 跨鏈消息偽造（Gateway Bypass）
```solidity
// ❌ 漏洞代碼 - CrossCurve ($3M, Feb 2026)
// ReceiverAxelar 缺少 gateway 驗證
function expressExecute(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload
) external {
    // 缺少: 驗證 msg.sender == gateway
    // 缺少: 驗證 commandId 是否已由 gateway 確認
    _execute(sourceChain, sourceAddress, payload);
}
```

```solidity
// ✅ 安全代碼
function expressExecute(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload
) external {
    // 驗證命令已由 gateway 批准
    require(
        gateway.isCommandExecuted(commandId) == false,
        "already executed"
    );
    bytes32 payloadHash = keccak256(payload);
    require(
        gateway.validateContractCall(
            commandId, sourceChain, sourceAddress, payloadHash
        ),
        "not approved by gateway"
    );
    _execute(sourceChain, sourceAddress, payload);
}
```

**檢測要點:**
- 跨鏈接收函數是否驗證了消息來自合法 gateway/relayer
- `expressExecute` 等快速通道是否有獨立驗證
- 是否可以重放已執行的命令

---

## 2. 私鑰/多簽管理漏洞（Key Management Vulnerabilities）

### 描述
許多橋接依賴少數驗證者的私鑰進行多簽。如果 threshold 過低或密鑰管理不當，攻擊者可以控制整個橋。

### 漏洞模式

#### 2.1 低 Threshold 多簽
```
// ❌ 問題配置 - Ronin Bridge ($625M)
// 9 個驗證者，只需 5/9 簽名
// 其中 4 個由同一實體（Sky Mavis）控制
// 第 5 個是 Axie DAO，之前授權給 Sky Mavis 但未撤銷

// ❌ 問題配置 - Harmony Bridge ($100M)
// 只需 2/5 多簽
// 攻擊者只需攻破 2 個密鑰

// ❌ 問題配置 - Orbit Chain ($81M)
// 10 個簽名者，7 個被攻破
// 但 threshold 可能過低
```

**檢測要點:**
- Threshold 是否 >= 2/3 的簽名者總數
- 簽名者是否由獨立實體控制（非同一組織）
- 是否有密鑰輪換機制
- 廢棄的臨時授權是否已撤銷
- 多簽合約是否可以單方面升級

#### 2.2 單一 Deployer/CEO 控制
```solidity
// ❌ 漏洞模式 - Multichain ($130M)
// CEO 個人控制所有驗證者密鑰
// 無多簽，無 timelock，無治理

// 審計檢查:
// 1. 誰控制 admin/owner 角色？
// 2. 是否有單一密鑰可以升級合約？
// 3. 是否有單一密鑰可以暫停橋接？
// 4. 資金是否可以被單一密鑰提取？
```

#### 2.3 Guardian Set 更新漏洞
```solidity
// ❌ 漏洞代碼
function updateGuardianSet(
    address[] calldata newGuardians,
    uint32 newIndex
) external {
    require(msg.sender == governance, "not governance");
    // 缺少: 驗證 newGuardians 不包含重複地址
    // 缺少: 驗證 newGuardians.length >= minGuardians
    // 缺少: 時間鎖延遲
    guardianSets[newIndex] = GuardianSet(newGuardians, block.timestamp);
    currentGuardianSetIndex = newIndex;
}
```

```solidity
// ✅ 安全代碼
function updateGuardianSet(
    address[] calldata newGuardians,
    uint32 newIndex
) external onlyGovernance timelocked(48 hours) {
    require(newGuardians.length >= MIN_GUARDIANS, "too few");
    require(newIndex == currentGuardianSetIndex + 1, "wrong index");
    
    // 檢查無重複
    for (uint i = 0; i < newGuardians.length; i++) {
        require(newGuardians[i] != address(0), "zero address");
        for (uint j = i + 1; j < newGuardians.length; j++) {
            require(newGuardians[i] != newGuardians[j], "duplicate");
        }
    }
    
    guardianSets[newIndex] = GuardianSet(newGuardians, block.timestamp);
    currentGuardianSetIndex = newIndex;
    
    // 舊 guardian set 在過期時間後失效
    guardianSets[newIndex - 1].expiryTime = block.timestamp + GUARDIAN_SET_EXPIRY;
}
```

---

## 3. Lock/Mint 不一致性（Asset Accounting Mismatch）

### 描述
橋接的基本不變量：鎖定量 = 鑄造量。任何破壞此不變量的漏洞都可能導致無限鑄造或資金竊取。

### 漏洞模式

#### 3.1 無抵押鑄造（Unbacked Minting）
```solidity
// ❌ 漏洞代碼 - Qubit ($80M)
// deposit() 使用 safeTransferFrom，但 depositETH() 有不同邏輯
function deposit(address token, uint256 amount) external {
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    emit Deposited(msg.sender, token, amount);
}

// ETH 存款函數檢查 msg.value
function depositETH() external payable {
    emit Deposited(msg.sender, ETH_ADDRESS, msg.value);
}

// 但 QBridge 合約的 deposit(ETH_ADDRESS, amount) 可以被調用
// 且不檢查 msg.value，允許 0 ETH 存款觸發跨鏈鑄造
```

```solidity
// ✅ 安全代碼
function deposit(address token, uint256 amount) external payable {
    if (token == ETH_ADDRESS) {
        require(msg.value == amount && amount > 0, "invalid ETH");
    } else {
        require(msg.value == 0, "unexpected ETH");
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - balBefore;
        amount = received; // 使用實際收到的數量（處理 fee-on-transfer）
    }
    require(amount > 0, "zero amount");
    emit Deposited(msg.sender, token, amount);
}
```

#### 3.2 Fee-on-Transfer Token 不一致
```solidity
// ❌ 漏洞代碼
function lock(address token, uint256 amount) external {
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    // 如果 token 有轉帳手續費，實際收到的 < amount
    // 但跨鏈消息告訴目標鏈鑄造 amount
    _sendCrossChainMessage(token, msg.sender, amount);
}
```

**檢測要點:**
- 是否使用 balance-before/after 模式記錄實際收到的數量
- Rebasing token 是否正確處理
- Fee-on-transfer token 是否考慮
- 鎖定/解鎖是否有 amount=0 保護

#### 3.3 Wrapped Token 匯率操控
```solidity
// ❌ 漏洞代碼 - Meter.io ($4.4M)
// 對 wrapped native token (wETH/wBNB) 的特殊處理有 bug
function deposit(address token, uint256 amount) external payable {
    if (token == WETH) {
        // 假設 msg.value 等於 amount，但未驗證
        // 攻擊者可以發送 0 ETH 但指定大 amount
        IWETH(WETH).deposit{value: msg.value}();
    }
    emit Deposited(msg.sender, token, amount);
}
```

---

## 4. 重放攻擊（Replay Attacks）

### 描述
跨鏈消息如果缺少防重放保護，同一筆提款可以被多次執行。

### 漏洞模式

#### 4.1 缺少 Nonce/已處理標記
```solidity
// ❌ 漏洞代碼
function executeWithdraw(
    bytes32 txHash,
    address token,
    address to,
    uint256 amount,
    bytes[] calldata signatures
) external {
    // 缺少: 檢查 txHash 是否已處理
    require(verifySignatures(txHash, signatures), "bad sigs");
    IERC20(token).safeTransfer(to, amount);
}
```

```solidity
// ✅ 安全代碼
mapping(bytes32 => bool) public processedMessages;

function executeWithdraw(
    bytes32 messageId,
    address token,
    address to,
    uint256 amount,
    uint256 srcChainId,
    bytes[] calldata signatures
) external {
    // 防重放
    require(!processedMessages[messageId], "already processed");
    processedMessages[messageId] = true;
    
    // 包含 chainId 防止跨鏈重放
    bytes32 digest = keccak256(abi.encode(
        messageId, token, to, amount, srcChainId, block.chainid
    ));
    require(verifySignatures(digest, signatures), "bad sigs");
    
    IERC20(token).safeTransfer(to, amount);
}
```

#### 4.2 跨鏈 Chain ID 缺失
```solidity
// ❌ 消息不包含 chain ID，可以在不同鏈上重放
bytes32 hash = keccak256(abi.encode(to, token, amount, nonce));

// ✅ 消息包含源鏈和目標鏈 ID
bytes32 hash = keccak256(abi.encode(
    to, token, amount, nonce, 
    sourceChainId, destinationChainId
));
```

#### 4.3 硬分叉後重放
```
// 情境：鏈發生硬分叉（如 ETH→ETH+ETC）
// 風險：在一條鏈上的操作可以在另一條鏈上重放
// 防禦：消息中包含 block.chainid（EIP-155）
// 注意：block.chainid 在分叉後會改變
```

---

## 5. 流動性池/Vault 攻擊（Liquidity Pool Attacks）

### 描述
某些橋接使用流動性池而非 lock-and-mint 模式。這引入了額外的 DeFi 攻擊面。

### 漏洞模式

#### 5.1 閃電貸耗盡流動性
```solidity
// 攻擊流程:
// 1. 閃電貸借出大量代幣
// 2. 通過橋接發送大量跨鏈請求
// 3. 耗盡目標鏈上的流動性
// 4. 以優惠價格獲取目標鏈資產
// 5. 歸還閃電貸

// 防禦: 單筆/單塊轉帳限額 + 流動性門檻
```

#### 5.2 橋接 Token 脫鉤
```
// 風險: 如果鎖定的原始代幣被盜或鎖定合約被攻破
// wrapped token 失去支撐 → 脫鉤 → 持有者損失

// 案例: Multichain 被攻破後，所有通過它鑄造的 wrapped token
// (anyUSDC, anyETH 等) 瞬間失去價值

// 審計檢查:
// 1. wrapped token 是否有 mint 權限控制
// 2. 是否有多個 minter（非單一橋接）
// 3. 是否有儲備證明機制
// 4. 是否有緊急暫停保護
```

---

## 6. Relayer/Oracle 操控（Relayer & Oracle Manipulation）

### 描述
橋接 relayer 負責在鏈間傳遞消息。如果 relayer 被攻破或 oracle 數據被操控，橋接安全就會被破壞。

### 漏洞模式

#### 6.1 Relayer 審查/延遲攻擊
```
// 風險: Relayer 可以選擇性延遲或忽略某些跨鏈消息
// 影響:
// - 清算消息被延遲 → 借貸協議損失
// - 價格更新被延遲 → 套利機會
// - 治理提案結果被延遲 → 操控

// 審計檢查:
// 1. 用戶是否可以自行提交證明（permissionless relay）
// 2. 是否有消息過期時間
// 3. 是否有多個 relayer（去中心化）
// 4. Relayer 是否有 stake（作惡可被罰沒）
```

#### 6.2 Oracle 數據篡改
```solidity
// ❌ 漏洞代碼
// 使用單一 oracle 確認跨鏈事件
function confirmDeposit(
    bytes32 txHash,
    uint256 amount
) external onlyOracle {
    // 單一 oracle 可以偽造任意存款
    _mintWrapped(msg.sender, amount);
}
```

```solidity
// ✅ 安全代碼 - 多層驗證 (如 Chainlink CCIP 架構)
// 1. 主 DON（Decentralized Oracle Network）驗證消息
// 2. 獨立 Risk Management Network 二次驗證
// 3. 任一層檢測異常可暫停橋接

function confirmDeposit(
    bytes32 txHash,
    uint256 amount,
    bytes[] calldata donSignatures,
    bytes[] calldata riskNetSignatures
) external {
    require(verifyDON(txHash, amount, donSignatures), "DON rejected");
    require(verifyRiskNet(txHash, amount, riskNetSignatures), "Risk rejected");
    _mintWrapped(msg.sender, amount);
}
```

---

## 7. 升級與治理攻擊（Upgrade & Governance Attacks）

### 描述
橋接合約通常是可升級的（proxy pattern）。如果升級權限被攻破，攻擊者可以部署惡意實現來竊取所有鎖定資金。

### 漏洞模式

#### 7.1 無 Timelock 升級
```solidity
// ❌ 漏洞代碼 - ALEX Bridge ($4.3M)
// Deployer 直接升級合約，無 timelock
function upgrade(address newImpl) external onlyOwner {
    _upgradeTo(newImpl);
}

// 攻擊流程:
// 1. 攻破 deployer 私鑰
// 2. 部署惡意合約
// 3. 調用 upgrade()
// 4. 調用惡意函數提取所有鎖定資金
// 5. 整個過程可在一個交易中完成
```

```solidity
// ✅ 安全代碼
uint256 public constant UPGRADE_DELAY = 48 hours;
mapping(address => uint256) public pendingUpgrades;

function proposeUpgrade(address newImpl) external onlyGovernance {
    pendingUpgrades[newImpl] = block.timestamp + UPGRADE_DELAY;
    emit UpgradeProposed(newImpl, block.timestamp + UPGRADE_DELAY);
}

function executeUpgrade(address newImpl) external onlyGovernance {
    require(pendingUpgrades[newImpl] != 0, "not proposed");
    require(block.timestamp >= pendingUpgrades[newImpl], "too early");
    delete pendingUpgrades[newImpl];
    _upgradeTo(newImpl);
}

function cancelUpgrade(address newImpl) external onlyGuardian {
    delete pendingUpgrades[newImpl];
    emit UpgradeCancelled(newImpl);
}
```

---

## 8. 速率限制與緊急機制（Rate Limiting & Circuit Breakers）

### 描述
即使存在漏洞，適當的速率限制和緊急暫停機制可以大幅降低損失。

### 漏洞模式

#### 8.1 缺少提款速率限制
```solidity
// ❌ 橋接無任何限制，一次攻擊可以提取所有資金

// ✅ 安全代碼
uint256 public constant RATE_LIMIT_PERIOD = 1 hours;
uint256 public constant MAX_WITHDRAW_PER_PERIOD = 1_000_000e18; // $1M/hour
uint256 public currentPeriodWithdrawals;
uint256 public currentPeriodStart;

function withdraw(address token, address to, uint256 amount) internal {
    // 更新速率限制
    if (block.timestamp >= currentPeriodStart + RATE_LIMIT_PERIOD) {
        currentPeriodStart = block.timestamp;
        currentPeriodWithdrawals = 0;
    }
    currentPeriodWithdrawals += amount;
    require(
        currentPeriodWithdrawals <= MAX_WITHDRAW_PER_PERIOD,
        "rate limit exceeded"
    );
    
    IERC20(token).safeTransfer(to, amount);
}
```

#### 8.2 暫停機制不完整
```solidity
// ❌ 問題: 暫停只阻止新存款，不阻止提款
function deposit() external whenNotPaused { ... }
function withdraw() external { ... } // 沒有 whenNotPaused！

// ✅ 存款和提款都應可暫停
function deposit() external whenNotPaused { ... }
function withdraw() external whenNotPaused { ... }

// ✅ 更好: 獨立暫停開關
bool public depositsPaused;
bool public withdrawalsPaused;
```

#### 8.3 大額轉帳無延遲
```solidity
// ✅ 安全設計: 大額轉帳增加觀察期
function processWithdraw(bytes32 messageId, uint256 amount) internal {
    if (amount > LARGE_TRANSFER_THRESHOLD) {
        // 大額轉帳需要等待觀察期
        pendingWithdrawals[messageId] = PendingWithdraw({
            amount: amount,
            unlockTime: block.timestamp + LARGE_TRANSFER_DELAY,
            // ...
        });
        emit LargeTransferPending(messageId, amount);
    } else {
        _executeWithdraw(messageId);
    }
}
```

---

## 9. L2 Canonical Bridge 特有風險

### 描述
L2 的原生橋（canonical bridge）有與通用橋不同的風險模型，尤其涉及 sequencer、challenge period 和消息延遲。

### 漏洞模式

#### 9.1 Challenge Period 繞過
```
// Optimistic Rollup 的 L2→L1 提款需要 7 天 challenge period
// 風險:
// 1. Sequencer 提交虛假 state root
// 2. 如果無人在 7 天內挑戰，虛假狀態被接受
// 3. 攻擊者可以在 L1 上提取不存在的資金

// 審計檢查:
// - 是否有足夠的挑戰者監控
// - challenge period 是否足夠長
// - 是否有快速提款服務（可能引入新風險）
```

#### 9.2 L1→L2 消息重試風險
```solidity
// Arbitrum Retryable Tickets 風險
// 如果 L2 執行失敗（gas 不足），ticket 可以被任何人重試
// 但如果 ticket 過期（7 天），資金可能永久丟失

// ❌ 漏洞: 依賴 L1→L2 消息但不處理失敗情況
function bridgeToL2(uint256 amount) external {
    // 如果 L2 gas 價格飆升，消息可能失敗
    // 用戶資金卡在中間狀態
    inbox.createRetryableTicket{value: msg.value}(
        l2Target, 0, 0, msg.sender, msg.sender,
        maxGas, gasPriceBid, data
    );
}
```

#### 9.3 Sequencer 下線時的橋接風險
```
// Sequencer 下線時:
// 1. L2 上的交易暫停
// 2. 但 L1 上的存款可能繼續
// 3. Sequencer 恢復後，積壓的存款可能導致:
//    - 價格陳舊
//    - 清算浪潮
//    - 套利機會

// 審計檢查:
// - 是否有 sequencer uptime feed (如 Chainlink)
// - 是否在 sequencer 下線時暫停敏感操作
// - 恢復後是否有 grace period
```

---

## 10. Token 映射與部署風險

### 描述
橋接需要在目標鏈上部署 wrapped token 或維護 token 映射表。錯誤的映射可以導致資金損失。

### 漏洞模式

#### 10.1 假 Token 映射
```solidity
// ❌ 漏洞代碼
// 任何人可以創建 token 映射
function createMapping(
    address sourceToken,
    string calldata name,
    string calldata symbol
) external returns (address wrappedToken) {
    // 缺少: 驗證 sourceToken 是否真的存在於源鏈
    // 缺少: 驗證 caller 是否有權限
    wrappedToken = _deployWrapped(name, symbol);
    tokenMapping[sourceToken] = wrappedToken;
}
```

#### 10.2 Token Decimals 不匹配
```solidity
// ❌ 問題: 源鏈 USDC 是 6 decimals，但 wrapped 版本是 18 decimals
// 橋接如果不做轉換，1 USDC 會變成 1e-12 wUSDC 或反之

// ✅ 安全代碼
function bridgeToken(address token, uint256 amount) external {
    uint8 srcDecimals = IERC20Metadata(token).decimals();
    uint8 dstDecimals = wrappedTokenDecimals[token];
    
    uint256 normalizedAmount;
    if (srcDecimals > dstDecimals) {
        normalizedAmount = amount / (10 ** (srcDecimals - dstDecimals));
        require(normalizedAmount * (10 ** (srcDecimals - dstDecimals)) == amount, 
            "precision loss");
    } else {
        normalizedAmount = amount * (10 ** (dstDecimals - srcDecimals));
    }
    
    _lock(token, amount);
    _sendMintMessage(token, msg.sender, normalizedAmount);
}
```

---

## 真實案例研究

| 案例 | 日期 | 損失 | 漏洞類型 | 根本原因 |
|------|------|------|----------|----------|
| **Ronin Bridge** | 2022-03 | $625M | 私鑰管理 | 5/9 驗證者密鑰被攻破，4 個由同一實體控制 |
| **Poly Network** | 2021-08 | $612M | 訪問控制 | 跨鏈消息可以調用特權函數更改 keeper |
| **BNB Bridge** | 2022-10 | $566M | 證明驗證 | IAVL 證明驗證存在漏洞，允許偽造存款 |
| **Wormhole** | 2022-02 | $326M | 簽名驗證 | 未驗證 secp256k1 指令來源，允許偽造 guardian 簽名 |
| **Nomad** | 2022-08 | $190M | 初始化錯誤 | 升級將 trusted root 設為 0x00，所有消息自動通過 |
| **Multichain** | 2023-07 | $130M | 中心化密鑰 | CEO 個人控制所有 MPC 密鑰 |
| **Harmony** | 2022-06 | $100M | 低 threshold | 2/5 多簽，攻破 2 個密鑰即可 |
| **Orbit Chain** | 2024-01 | $81M | 私鑰管理 | 7/10 簽名者密鑰被攻破 |
| **Qubit** | 2022-01 | $80M | 邏輯錯誤 | deposit(ETH_ADDRESS, amount) 不檢查 msg.value |
| **Socket** | 2024-01 | $3.3M | 未驗證輸入 | 動態路由中的 calldata 未經驗證 |
| **CrossCurve** | 2026-02 | $3M | Gateway 繞過 | ReceiverAxelar 缺少 gateway 驗證 |

---

## 橋接審計清單

### A. 消息驗證
- [ ] 所有跨鏈消息是否經過多方驗證？
- [ ] 消息是否包含源鏈 ID、目標鏈 ID、nonce？
- [ ] 是否有防重放機制（processed mapping）？
- [ ] 簽名驗證是否使用正確的 precompile/program？
- [ ] ecrecover 返回 address(0) 是否被拒絕？
- [ ] 零值 root/hash 是否被特殊處理？
- [ ] Express/fast path 是否有獨立驗證？

### B. 資產會計
- [ ] lock amount == mint amount（扣除費用後）？
- [ ] 是否使用 balance-before/after 處理 fee-on-transfer token？
- [ ] Token decimals 是否在跨鏈時正確轉換？
- [ ] 0 amount 存款/提款是否被拒絕？
- [ ] Rebasing token 是否正確處理？
- [ ] Native token (ETH) 和 wrapped token 的處理是否一致？

### C. 密鑰管理
- [ ] Threshold >= 2/3 的簽名者總數？
- [ ] 簽名者由獨立實體控制？
- [ ] 是否有密鑰輪換/撤銷機制？
- [ ] Guardian set 更新是否有 timelock？
- [ ] 過期的 guardian set 是否被禁用？

### D. 速率限制與緊急機制
- [ ] 是否有單筆最大轉帳限額？
- [ ] 是否有時間窗口內的累計限額？
- [ ] 大額轉帳是否有額外延遲？
- [ ] 暫停機制是否同時涵蓋存款和提款？
- [ ] Guardian/安全委員會是否可以緊急暫停？
- [ ] 是否有異常檢測和自動暫停？

### E. 升級安全
- [ ] 合約升級是否有 timelock（>= 48h）？
- [ ] L2 橋接升級 timelock 是否 > challenge period（7 天）？
- [ ] 是否有升級取消機制（guardian veto）？
- [ ] 升級後的合約是否經過審計？
- [ ] Storage layout 是否兼容？

### F. Token 映射
- [ ] Token 映射創建是否需要權限？
- [ ] 是否驗證了 token decimals 一致性？
- [ ] Wrapped token mint 權限是否僅限於橋接合約？
- [ ] 是否有機制處理源鏈 token 升級/遷移？

---

*最後更新: 2026-02-12 02:00 AM*
*來源: Ronin, Wormhole, Nomad, Poly Network, BNB Bridge, Qubit, Meter.io, Multichain, Harmony, Orbit Chain, Socket, ALEX, CrossCurve 事後分析*
