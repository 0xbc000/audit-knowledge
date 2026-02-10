# Governance & DAO Attack Patterns

> 治理攻擊是 DeFi 中最具破壞力的攻擊類型之一。攻擊者利用治理機制的設計缺陷，
> 通過合法的投票流程竊取協議資金。由於治理操作通常擁有最高權限，一次成功的治理攻擊
> 往往造成協議級別的災難性損失。

## 1. Flash Loan Governance Attack（閃電貸治理攻擊）

**嚴重性:** CRITICAL  
**真實案例:** Beanstalk ($182M, April 2022)

### 攻擊原理
攻擊者通過閃電貸在單一交易中借入大量治理代幣，獲得多數投票權，
提交並執行惡意提案，然後歸還借款。整個攻擊在一個區塊內完成。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: 投票和執行在同一區塊
contract VulnerableGovernor {
    function propose(address[] calldata targets, bytes[] calldata calldatas) external {
        require(getVotes(msg.sender) >= proposalThreshold(), "below threshold");
        // 提案立即生效...
    }
    
    function execute(uint256 proposalId) external {
        require(state(proposalId) == ProposalState.Succeeded, "not succeeded");
        // ⚠️ 無時間延遲！可以在同一區塊投票+執行
        for (uint256 i = 0; i < targets.length; i++) {
            targets[i].call(calldatas[i]);
        }
    }
    
    // ⚠️ 使用當前餘額而非快照
    function getVotes(address account) public view returns (uint256) {
        return token.balanceOf(account);  // 可被閃電貸操控
    }
}
```

```solidity
// ✅ SECURE: 快照投票 + 時間鎖
contract SecureGovernor {
    uint256 public constant VOTING_DELAY = 1 days;   // 提案→投票開始
    uint256 public constant VOTING_PERIOD = 3 days;   // 投票持續時間
    uint256 public constant TIMELOCK_DELAY = 2 days;  // 通過→執行延遲
    
    function getVotes(address account, uint256 blockNumber) public view returns (uint256) {
        // 使用提案創建時的快照，閃電貸無法影響歷史餘額
        return token.getPastVotes(account, blockNumber);
    }
    
    function execute(uint256 proposalId) external {
        require(state(proposalId) == ProposalState.Queued, "not queued");
        require(block.timestamp >= proposals[proposalId].eta, "timelock not expired");
        // 執行...
    }
}
```

### Beanstalk 攻擊流程
1. 攻擊者通過 Aave 閃電貸借入 ~$1B 資產
2. 將資產換成 BEAN 代幣，獲得 67% 投票權
3. 投票通過 BIP-18 提案：將流動池資產轉給攻擊者
4. 立即執行提案（emergency governance 無延遲）
5. 歸還閃電貸，淨利潤 $77M（協議總損失 $182M）

### 檢測要點
- [ ] 投票權是否使用快照（`getPastVotes`）而非當前餘額
- [ ] 提案創建到投票開始是否有延遲（`votingDelay > 0`）
- [ ] 投票通過到執行是否有 timelock
- [ ] 是否存在可繞過延遲的 emergency 執行路徑
- [ ] emergency 路徑是否有額外的安全檢查（多簽、更高門檻）

---

## 2. Fake Proposal / Trojan Proposal（偽造提案攻擊）

**嚴重性:** CRITICAL  
**真實案例:** Tornado Cash ($2.17M, May 2023)

### 攻擊原理
攻擊者提交一個看似無害的提案合約，通過投票後，利用 `selfdestruct` + `CREATE2` 
在相同地址部署完全不同的惡意合約，替換原始提案邏輯。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: 提案合約可以自毀並被替換
contract MaliciousProposal {
    // 第一次部署：看起來無害
    function executeProposal() external {
        // 合法的治理操作...
    }
    
    // 隱藏的自毀函數
    function emergencyStop() external {
        selfdestruct(payable(msg.sender));
        // 自毀後，攻擊者用 CREATE2 在相同地址部署惡意合約
    }
}

// 替換後的合約（相同地址）
contract ReplacedMalicious {
    function executeProposal() external {
        // 惡意操作：轉移所有鎖定的 TORN 代幣
        torn.transfer(attacker, torn.balanceOf(address(governance)));
    }
}
```

```solidity
// ✅ SECURE: 驗證提案合約代碼哈希
contract SecureGovernor {
    mapping(uint256 => bytes32) public proposalCodeHash;
    
    function propose(address proposalContract) external {
        bytes32 codeHash;
        assembly { codeHash := extcodehash(proposalContract) }
        proposalCodeHash[proposalId] = codeHash;
    }
    
    function execute(uint256 proposalId) external {
        // 執行前驗證合約代碼未被替換
        bytes32 currentHash;
        assembly { currentHash := extcodehash(proposals[proposalId].target) }
        require(currentHash == proposalCodeHash[proposalId], "code changed");
        // 執行...
    }
}
```

### Tornado Cash 攻擊流程
1. 攻擊者部署提案合約 C503893，聲稱與前一個合法提案相同
2. 提案通過社區投票
3. 攻擊者調用 `emergencyStop()` 自毀提案合約
4. 使用 `CREATE2` 在相同地址部署惡意合約
5. 執行提案時，惡意合約賦予攻擊者 10,000 票投票權
6. 攻擊者控制治理，提取並出售 TORN 代幣獲利 ~$1M

### 檢測要點
- [ ] 提案合約是否包含 `selfdestruct`
- [ ] 提案合約是否使用 `delegatecall` 到可變地址
- [ ] 執行前是否驗證合約 `extcodehash` 未變
- [ ] 是否限制提案只能由 EOA 創建（防止 CREATE2 技巧）
- [ ] 是否使用提案模板限制合約結構

---

## 3. Proposal Execution Ordering Attack（提案執行排序攻擊）

**嚴重性:** HIGH  
**真實案例:** Sonne Finance ($20M, May 2024)

### 攻擊原理
多步驟提案的各個交易可以被任何人觸發執行，且不強制執行順序。
攻擊者選擇性地執行部分步驟，跳過關鍵的安全初始化步驟。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: 多步驟提案無順序保證
contract VulnerableTimelock {
    // 提案包含多個操作，但各操作獨立可執行
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,  // ⚠️ predecessor = 0 表示無前置條件
        bytes32 salt
    ) external {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        require(isOperationReady(id), "not ready");
        // 執行單一操作
        target.call{value: value}(data);
    }
}

// Sonne Finance 提案步驟:
// Step 1: 添加新市場 cVELO ← 攻擊者執行了這步
// Step 2: 設置初始供應量 ← 攻擊者跳過這步
// Step 3: 配置參數 ← 攻擊者跳過這步
// 結果：空市場暴露了已知的 Compound fork 漏洞
```

```solidity
// ✅ SECURE: 打包為原子操作
contract SecureTimelock {
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) external {
        // 所有操作作為原子交易執行，要麼全部成功，要麼全部回滾
        bytes32 id = hashOperationBatch(targets, values, payloads, predecessor, salt);
        require(isOperationReady(id), "not ready");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call{value: values[i]}(payloads[i]);
            require(success, "execution failed");
        }
    }
}
```

### 檢測要點
- [ ] 多步驟提案是否打包為 `executeBatch`
- [ ] 單獨可執行的步驟是否有 `predecessor` 依賴
- [ ] 提案執行者是否有限制（不是任何人都能觸發）
- [ ] 新市場/新功能啟用是否在原子操作中完成初始化

---

## 4. Low Quorum / Vote Manipulation（低法定人數/投票操縱）

**嚴重性:** HIGH  
**真實案例:** Compound (Humpy, 2024), Swerve Finance ($1.3M, 2023)

### 攻擊原理
攻擊者利用低投票參與率，以較小的代幣持有量通過惡意提案。
或者在廢棄項目中廉價收購足夠投票權控制治理。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: 固定低法定人數
contract VulnerableGovernor {
    uint256 public constant QUORUM = 400_000e18;  // 固定數量
    // 當代幣總供應增長或價格下跌時，收購成本大幅降低
    
    function _quorumReached(uint256 proposalId) internal view returns (bool) {
        return proposals[proposalId].forVotes >= QUORUM;
    }
}

// ❌ VULNERABLE: 無投票權衰減
contract NoDecayGovernor {
    // 代幣可以無限期持有投票權，不需要鎖定
    // 攻擊者可以在投票前一刻買入，投票後立即賣出
    function castVote(uint256 proposalId, uint8 support) external {
        uint256 weight = getVotes(msg.sender, proposalSnapshot(proposalId));
        // 只要在快照時持有就行
    }
}
```

```solidity
// ✅ SECURE: 動態法定人數 + 投票鎖定
contract SecureGovernor {
    // 法定人數為總供應的百分比
    function quorum(uint256 blockNumber) public view returns (uint256) {
        return token.getPastTotalSupply(blockNumber) * quorumNumerator / quorumDenominator;
    }
    
    // 投票時鎖定代幣，防止閃進閃出
    function castVote(uint256 proposalId, uint8 support) external {
        uint256 weight = getVotes(msg.sender, proposalSnapshot(proposalId));
        // 鎖定代幣直到投票期結束
        token.lockUntil(msg.sender, proposals[proposalId].voteEnd);
    }
}
```

### Compound Humpy 案例
1. 大戶 Humpy 多次嘗試通過惡意提案
2. 利用 COMP 持有者的低參與率（290K 地址中僅 57 個投票）
3. 成功通過提案 289：授予其團體 499,000 COMP（成為最大投票代理）
4. 最終通過協商解決（而非技術手段）

### Swerve Finance 案例
1. 開發團隊棄項目，多簽失效
2. 攻擊者廉價收購足夠 SWRV 代幣
3. 通過提案將協議費用和流動性轉至攻擊者地址

### 檢測要點
- [ ] 法定人數是否為總供應的百分比（非固定數量）
- [ ] 法定人數比例是否合理（通常 4-10%）
- [ ] 是否有投票鎖定期防止閃進閃出
- [ ] 是否有反對票退出機制（rage quit）
- [ ] 大額投票權變動是否有監控/警報
- [ ] 項目是否有「守護者」機制可以否決明顯惡意提案

---

## 5. Multi-sig Compromise（多簽被攻破）

**嚴重性:** CRITICAL  
**真實案例:** Unleash Protocol ($3.9M, Dec 2025), Ronin Bridge ($625M, 2022)

### 攻擊原理
獲取多簽錢包的足夠簽名者私鑰，通過未授權的升級或轉帳竊取資金。
L2 場景下，攻擊者可通過橋接將資金轉至 L1 後混幣。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: 多簽門檻過低或簽名者集中
contract VulnerableMultisig {
    uint256 public threshold = 2;  // 只需 2/5
    address[] public owners;       // 部分 owner 可能是同一實體
    
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        bytes calldata signatures
    ) external {
        // ⚠️ 無延遲，立即執行
        // ⚠️ 無操作類型限制
        require(checkSignatures(to, value, data, signatures), "sigs invalid");
        to.call{value: value}(data);
    }
}
```

```solidity
// ✅ SECURE: 分層多簽 + 操作限制
contract SecureMultisig {
    uint256 public constant UPGRADE_THRESHOLD = 4;    // 升級需要 4/7
    uint256 public constant TRANSFER_THRESHOLD = 3;   // 轉帳需要 3/7
    uint256 public constant UPGRADE_DELAY = 48 hours;
    
    // 高風險操作（升級、大額轉帳）需要更高門檻 + 時間延遲
    function queueUpgrade(address newImpl) external onlyMultisig(UPGRADE_THRESHOLD) {
        upgradeQueue[newImpl] = block.timestamp + UPGRADE_DELAY;
        emit UpgradeQueued(newImpl, block.timestamp + UPGRADE_DELAY);
    }
    
    // 日限額保護
    uint256 public dailyLimit;
    mapping(uint256 => uint256) public dailySpent;  // day => amount
    
    function transfer(address to, uint256 amount) external onlyMultisig(TRANSFER_THRESHOLD) {
        uint256 today = block.timestamp / 1 days;
        require(dailySpent[today] + amount <= dailyLimit, "daily limit");
        dailySpent[today] += amount;
    }
}
```

### Unleash Protocol 攻擊流程 (Dec 30, 2025)
1. 攻擊者獲得多簽錢包控制權
2. 批准未授權的智能合約升級
3. 新合約允許自由提取代幣
4. 橋接 WIP、USDC、WETH、stIP、vIP 到 Ethereum
5. 1,337 ETH 通過 Tornado Cash 洗幣

### 檢測要點
- [ ] 多簽門檻是否足夠高（≥ 3/5 或 4/7）
- [ ] 簽名者是否為獨立實體（不同組織、不同地域）
- [ ] 是否使用硬體錢包
- [ ] 高風險操作（升級、大額轉帳）是否有額外延遲
- [ ] 是否有日/週限額
- [ ] 簽名者變更是否需要更高門檻
- [ ] 是否有鏈上監控和警報

---

## 6. Timelock Misconfiguration（時間鎖配置錯誤）

**嚴重性:** HIGH  
**真實案例:** 多個協議

### 攻擊原理
Timelock 設計不當：延遲過短、可被繞過、或在緊急模式下被跳過。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: Timelock 可被繞過
contract VulnerableTimelock {
    uint256 public delay = 2 days;
    
    // ⚠️ 管理員可以直接改 delay
    function setDelay(uint256 newDelay) external onlyAdmin {
        delay = newDelay;  // 可以設為 0！
    }
    
    // ⚠️ Emergency 模式完全繞過 timelock
    function emergencyExecute(address target, bytes calldata data) external onlyAdmin {
        target.call(data);  // 無延遲
    }
}
```

```solidity
// ✅ SECURE: Timelock 修改本身受 timelock 保護
contract SecureTimelock {
    uint256 public constant MIN_DELAY = 1 days;
    uint256 public constant MAX_DELAY = 30 days;
    uint256 public delay;
    
    // delay 修改本身需要通過 timelock
    function setDelay(uint256 newDelay) external onlySelf {
        require(newDelay >= MIN_DELAY && newDelay <= MAX_DELAY, "invalid delay");
        delay = newDelay;
    }
    
    // Emergency 有限制：只能暫停，不能轉帳/升級
    function emergencyPause() external onlyGuardian {
        paused = true;
        // 恢復仍需通過正常 timelock 流程
    }
}
```

### 檢測要點
- [ ] Timelock delay 是否有最小值保護
- [ ] delay 修改是否本身受 timelock 約束
- [ ] emergency 功能是否有操作範圍限制（只能暫停/不能升級/不能轉帳）
- [ ] emergency 是否需要多簽或更高門檻
- [ ] Timelock 是否覆蓋所有高權限操作

---

## 7. Delegation & Vote Counting Bugs（委託與計票漏洞）

**嚴重性:** MEDIUM-HIGH

### 攻擊原理
委託機制的實現缺陷允許雙重投票、投票權放大或投票權泄漏。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: 委託後轉移代幣可雙重投票
contract VulnerableDelegation {
    function delegate(address delegatee) external {
        _delegates[msg.sender] = delegatee;
        // ⚠️ 未在轉帳時更新委託投票權
    }
    
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        // ⚠️ 忘記更新委託的投票權！
        // 結果：delegatee 仍有原始投票權，to 也獲得投票權
    }
}

// ❌ VULNERABLE: unstake → transfer → restake 投票重複
// (來自 Salty.IO DEX 分析)
contract VulnerableStaking {
    function unstake(uint256 amount) external {
        stakes[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
        // 投票權隨 stake 移除
    }
    // 攻擊者：unstake → transfer to alt → alt stakes → alt votes
    // 效果：同一筆代幣投了兩次票
}
```

```solidity
// ✅ SECURE: ERC20Votes 自動追蹤委託
contract SecureVoting is ERC20Votes {
    // OpenZeppelin ERC20Votes 自動在轉帳時更新投票權
    function _afterTokenTransfer(address from, address to, uint256 amount) internal override {
        super._afterTokenTransfer(from, to, amount);
        _moveVotingPower(delegates(from), delegates(to), amount);
    }
}
```

### 檢測要點
- [ ] 代幣轉帳是否正確更新委託的投票權
- [ ] 是否使用 checkpoint 機制防止同快照內雙重投票
- [ ] unstake/transfer/restake 路徑是否有投票權重複風險
- [ ] 跨合約委託是否正確追蹤
- [ ] 自我委託是否正確處理

---

## 8. Governor Parameter Manipulation（治理參數操控）

**嚴重性:** MEDIUM

### 攻擊原理
通過治理流程修改治理參數本身（降低門檻、縮短延遲），
為後續惡意提案創造條件。

### 漏洞代碼

```solidity
// ❌ VULNERABLE: 治理參數可通過普通提案修改
contract VulnerableGovernor {
    function setVotingPeriod(uint256 newPeriod) external onlyGovernance {
        votingPeriod = newPeriod;  // 可以設為 1 個區塊
    }
    
    function setProposalThreshold(uint256 newThreshold) external onlyGovernance {
        proposalThreshold = newThreshold;  // 可以設為 0
    }
    
    function setQuorum(uint256 newQuorum) external onlyGovernance {
        quorumNumerator = newQuorum;  // 可以設為 1%
    }
}
```

```solidity
// ✅ SECURE: 參數修改有硬性邊界
contract SecureGovernor {
    uint256 constant MIN_VOTING_PERIOD = 1 days;
    uint256 constant MIN_QUORUM_NUMERATOR = 4;  // 最低 4%
    uint256 constant MIN_PROPOSAL_THRESHOLD = 1000e18;
    
    function setVotingPeriod(uint256 newPeriod) external onlyGovernance {
        require(newPeriod >= MIN_VOTING_PERIOD, "too short");
        votingPeriod = newPeriod;
    }
    
    function setQuorumNumerator(uint256 newNumerator) external onlyGovernance {
        require(newNumerator >= MIN_QUORUM_NUMERATOR, "too low");
        quorumNumerator = newNumerator;
    }
}
```

### 檢測要點
- [ ] 治理參數是否有硬性最小/最大值
- [ ] 參數修改是否需要更高門檻或更長延遲
- [ ] 是否存在「滑坡」路徑：連續修改參數逐步降低安全性
- [ ] 是否有守護者可以否決參數修改

---

## 9. Cross-Chain Governance Risks（跨鏈治理風險）

**嚴重性:** HIGH

### 攻擊原理
L2 上的治理系統可能受到 L1↔L2 消息延遲、sequencer 操控等影響。
跨鏈提案執行的時序差異可被利用。

### 漏洞場景

```solidity
// ❌ VULNERABLE: L2 治理不考慮 sequencer 風險
contract L2Governor {
    function castVote(uint256 proposalId, uint8 support) external {
        // ⚠️ Sequencer down 時用戶無法投票
        // ⚠️ Sequencer 可以選擇性包含/排除投票交易
        require(block.timestamp <= proposals[proposalId].voteEnd, "voting ended");
    }
}

// ❌ VULNERABLE: 跨鏈提案無同步機制
contract CrossChainGovernor {
    function executeOnL2(uint256 proposalId) external {
        // ⚠️ L1 timelock 過期後，L2 執行可能被延遲
        // 在延遲期間，條件可能已改變
        bridge.sendMessage(l2Executor, abi.encode(proposalId));
    }
}
```

```solidity
// ✅ SECURE: 考慮 sequencer downtime
contract SecureL2Governor {
    ISequencerUptimeFeed public sequencerFeed;
    uint256 public constant GRACE_PERIOD = 1 hours;
    
    function castVote(uint256 proposalId, uint8 support) external {
        uint256 voteEnd = proposals[proposalId].voteEnd;
        // 如果 sequencer 曾經 down，延長投票期
        (, , uint256 startedAt, , ) = sequencerFeed.latestRoundData();
        if (block.timestamp - startedAt < GRACE_PERIOD) {
            voteEnd += GRACE_PERIOD;  // 延長投票期
        }
        require(block.timestamp <= voteEnd, "voting ended");
    }
}
```

### 檢測要點
- [ ] L2 治理是否考慮 sequencer downtime 對投票的影響
- [ ] 跨鏈提案執行是否有過期機制
- [ ] 跨鏈消息是否可以被重放
- [ ] 橋接延遲是否被正確納入 timelock 計算

---

## 10. veToken / Vote-Escrow Governance Attacks（veToken 治理攻擊）

**嚴重性:** MEDIUM-HIGH

### 攻擊原理
Vote-escrow 模型（如 veCRV）中的鎖定機制可能被利用來操控投票權分配，
或者通過包裝器（wrapper）繞過鎖定限制。

### 漏洞場景

```solidity
// ❌ VULNERABLE: veToken 包裝器繞過鎖定
contract VeTokenWrapper {
    // 允許用戶存入 veToken 並獲得流動性代幣
    // 實際上繞過了 vote-escrow 的鎖定機制
    function deposit(uint256 amount) external {
        veToken.transferFrom(msg.sender, address(this), amount);
        liquidToken.mint(msg.sender, amount);
        // ⚠️ 包裝器控制了投票權，但持有者可以自由交易 liquidToken
    }
    
    // ⚠️ 投票權集中在包裝器，可被操控
    function vote(uint256 proposalId, uint8 support) external onlyOperator {
        governor.castVote(proposalId, support);
    }
}

// ❌ VULNERABLE: 投票權快照時間可預測
contract PredictableSnapshot {
    // 攻擊者可以在快照前最大化鎖定，快照後解鎖
    function getVotingPower(address user) external view returns (uint256) {
        // 投票權 = 鎖定量 × 剩餘鎖定時間
        return veToken.balanceOf(user);  // 只看當前快照
    }
}
```

### 檢測要點
- [ ] veToken 是否允許通過包裝器轉讓
- [ ] 投票權計算是否考慮鎖定時間衰減
- [ ] 是否有機制防止快照前後的戰略性鎖定/解鎖
- [ ] 大量 veToken 鎖定是否有警報
- [ ] 治理獎勵是否可能導致賄選

---

## 真實案例總結

| 案例 | 年份 | 損失 | 攻擊類型 | 根本原因 |
|------|------|------|----------|----------|
| The DAO | 2016 | $150M | Reentrancy | DAO 合約重入漏洞 |
| Beanstalk | 2022 | $182M | Flash Loan Voting | Emergency 投票無延遲 + 無快照 |
| Ronin Bridge | 2022 | $625M | Multi-sig Compromise | 5/9 多簽中 4 個由同一實體控制 |
| Tornado Cash | 2023 | $2.17M | Fake Proposal | CREATE2 地址替換 + selfdestruct |
| Swerve Finance | 2023 | $1.3M | Low Quorum | 廢棄項目 + 低投票參與 |
| Compound (Humpy) | 2024 | Near-miss | Low Quorum | 57/290K 地址投票 |
| Sonne Finance | 2024 | $20M | Execution Ordering | 多步驟提案無原子執行 |
| Unleash Protocol | 2025 | $3.9M | Multi-sig Takeover | 多簽控制權被獲取 + 合約升級 |

---

## 治理安全審計清單

### A. 投票機制
- [ ] A1: 使用快照投票權（`getPastVotes`）而非當前餘額
- [ ] A2: 提案創建到投票開始有足夠延遲（≥ 1 天）
- [ ] A3: 投票期足夠長（≥ 3 天）
- [ ] A4: 投票通過到執行有 timelock（≥ 2 天）
- [ ] A5: 法定人數為總供應百分比（4-10%）
- [ ] A6: 投票時鎖定代幣防止閃進閃出

### B. 提案安全
- [ ] B1: 提案合約是否可能被替換（selfdestruct/CREATE2）
- [ ] B2: 執行前驗證合約 codehash
- [ ] B3: 多步驟提案使用原子執行
- [ ] B4: 提案操作範圍是否有限制

### C. 時間鎖
- [ ] C1: Timelock delay 有最小值（≥ 1 天）
- [ ] C2: delay 修改受自身 timelock 保護
- [ ] C3: Emergency 操作有限制（僅暫停、不可升級/轉帳）
- [ ] C4: Emergency 需多簽或更高門檻

### D. 多簽安全
- [ ] D1: 多簽門檻 ≥ 3/5 或 4/7
- [ ] D2: 簽名者為獨立實體
- [ ] D3: 使用硬體錢包
- [ ] D4: 高風險操作有額外延遲
- [ ] D5: 日/週轉帳限額

### E. 委託機制
- [ ] E1: 轉帳時正確更新委託投票權
- [ ] E2: 無 unstake→transfer→restake 雙重投票
- [ ] E3: 自我委託正確處理

### F. 跨鏈治理
- [ ] F1: 考慮 sequencer downtime
- [ ] F2: 跨鏈提案有過期機制
- [ ] F3: Timelock > L2→L1 bridge delay

---

*文件建立: 2026-02-11 02:00 AM (Asia/Taipei)*
*來源: Beanstalk ($182M), Tornado Cash ($2.17M), Sonne Finance ($20M), Unleash Protocol ($3.9M), Compound, Swerve Finance, Sigma Prime 研究, SlowMist 分析*
