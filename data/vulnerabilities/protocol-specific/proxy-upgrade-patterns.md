# Proxy & Upgrade Vulnerability Patterns

> 可升級合約是 DeFi 最大的雙面刃：靈活性帶來巨大的攻擊面。
> 真實損失: Parity ($150M frozen), Audius ($6M), UPCX ($70M), Wormhole ($10M bounty), AllianceBlock (caught early)

---

## 1. Uninitialized Proxy / Implementation

### 漏洞描述
Proxy pattern 中，constructor 不會在 proxy context 下執行，必須使用 `initialize()` 函數。如果部署後忘記調用，或者只在 implementation 上直接調用（不通過 proxy），關鍵狀態變數（owner, guardian）保持 default zero 值，任何人都可以調用 `initialize()` 接管合約。

### 攻擊模式

#### 1a. Proxy 未初始化（UUPS 最危險）
```solidity
// ❌ 漏洞: Proxy 部署後沒有調用 initialize()
contract MyVault is UUPSUpgradeable, OwnableUpgradeable {
    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }
    
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// 攻擊: proxy 從未初始化，owner = address(0)
// 1. attacker 調用 proxy.initialize(attacker)
// 2. attacker 成為 owner
// 3. attacker 調用 upgradeTo(maliciousImpl)
// 4. 完全控制 proxy
```

#### 1b. Implementation 未鎖定
```solidity
// ❌ 漏洞: Implementation 的 constructor 沒有 _disableInitializers()
contract MyVaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    // 缺少: constructor() { _disableInitializers(); }
    
    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
    }
}

// 攻擊: 直接在 implementation 上調用 initialize()
// 在 UUPS 中，attacker 成為 implementation 的 owner
// 然後調用 upgradeTo() 指向含 selfdestruct 的合約
// delegatecall selfdestruct → proxy 被銷毀
```

### 安全代碼
```solidity
contract MyVaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers(); // ✅ 鎖定 implementation
    }
    
    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
    }
    
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}
}

// ✅ 部署時原子初始化
// deployProxy(MyVaultV1, [owner], { initializer: 'initialize' })
```

### 真實案例

**Wormhole ($10M bounty, 2022)**
- 跨鏈橋的 UUPS proxy 在一次升級後 implementation 變為未初始化
- 白帽調用 `initialize()` 成為 guardian
- 調用 `upgradeTo()` 指向含 `selfdestruct` 的合約
- 通過 `submitContractUpgrade` delegatecall → proxy 自毀
- 如果是惡意攻擊者，所有橋接資金將永久凍結

**Parity Multi-sig ($150M frozen, 2017)**
- Library 合約（類似 implementation）從未初始化
- 攻擊者調用 `initWallet()` 成為 owner
- 調用 `kill()` → selfdestruct
- 所有依賴該 library 的錢包永久凍結

### 檢測要點
- [ ] Implementation constructor 是否調用 `_disableInitializers()`？
- [ ] Proxy 部署是否在同一 tx 中調用 `initialize()`？
- [ ] `initialize()` 是否有 `initializer` modifier？
- [ ] 所有父合約的 `__init()` 是否都被調用？

---

## 2. Re-initialization Attack

### 漏洞描述
升級到新版本時，如果新增的 `initializeV2()` 處理不當，或者升級過程意外重置了 `initialized` flag，攻擊者可以再次調用初始化函數，重寫關鍵狀態變數。

### 攻擊模式
```solidity
// ❌ 漏洞: V2 升級引入新的初始化函數，但版本管理不當
contract MyVaultV2 is MyVaultV1 {
    uint256 public newParam;
    
    // 使用 reinitializer(2) 是正確的，但如果忘記...
    function initializeV2(uint256 _param) external {
        // 缺少 reinitializer(2) modifier!
        newParam = _param;
    }
}

// 更危險的情況: 升級重置了 initialized flag
contract MyVaultV2 is UUPSUpgradeable, OwnableUpgradeable {
    // 如果 storage layout 變了，initialized slot 可能被覆蓋
    // → initialized = false → 可以重新調用 initialize()
}
```

### 安全代碼
```solidity
contract MyVaultV2 is MyVaultV1 {
    uint256 public newParam;
    
    function initializeV2(uint256 _param) external reinitializer(2) {
        // ✅ reinitializer(2) 確保只能執行一次
        // ✅ 且版本必須 > 之前的版本
        newParam = _param;
    }
}
```

### 真實案例

**AllianceBlock (2024)**
- 升級 staking 合約時，新 implementation 的 `initialized` flag 被重置為 false
- 攻擊者調用 `initialize()`，更改了 `rewardToken`、`stakingToken`、`rewardRate`
- 設定無限獎勵率，可以用假 token 提取大量獎勵
- 幸運地被及時發現

### 檢測要點
- [ ] 升級是否使用 `reinitializer(N)` 而非 `initializer`？
- [ ] N 值是否 > 之前所有版本？
- [ ] 升級後 `initialized` 和 `_initializing` 值是否正確？
- [ ] `upgradeToAndCall` 是否原子性地執行新初始化？

---

## 3. Storage Layout Collision

### 漏洞描述
Proxy 的 storage 由 implementation 的變數佈局決定。如果升級時改變了變數順序、插入新變數、或修改繼承結構，storage slot 會錯位，導致數據被錯誤解讀。

### 攻擊模式

#### 3a. 變數插入導致 slot 偏移
```solidity
// V1
contract VaultV1 {
    address public owner;     // slot 0
    uint256 public totalDeposits; // slot 1
    mapping(address => uint256) public balances; // slot 2
}

// ❌ V2 在中間插入新變數
contract VaultV2 {
    address public owner;     // slot 0
    address public feeRecipient; // slot 1 ← 新插入!
    uint256 public totalDeposits; // slot 2 ← 偏移了!
    mapping(address => uint256) public balances; // slot 3 ← 偏移了!
}
// totalDeposits 現在讀到的是舊 balances mapping 的 root hash
// balances mapping 指向錯誤的 slot → 所有餘額丟失
```

#### 3b. 繼承變更導致 slot 碰撞
```solidity
// V1 繼承 A
contract A { uint256 public x; } // slot 0
contract VaultV1 is A {
    uint256 public y; // slot 1
}

// ❌ V2 移除了 A 的繼承
contract VaultV2 {
    uint256 public y; // slot 0 ← 現在讀到的是舊的 x!
}
```

#### 3c. Proxy 自身宣告 storage 變數
```solidity
// ❌ Proxy 合約自己宣告了 storage 變數（不在 EIP-1967 slot）
contract BadProxy {
    address public admin; // slot 0 ← 與 implementation 的 slot 0 衝突!
    
    fallback() external {
        // delegatecall to implementation...
    }
}
```

### 安全代碼
```solidity
// ✅ 使用 __gap 保留空間
contract VaultV1 is OwnableUpgradeable {
    uint256 public totalDeposits;
    mapping(address => uint256) public balances;
    
    uint256[48] private __gap; // 保留 48 個 slot 給未來升級
}

// ✅ V2 從 gap 中「借用」slot
contract VaultV2 is OwnableUpgradeable {
    uint256 public totalDeposits;
    mapping(address => uint256) public balances;
    address public feeRecipient; // 新變數放在末尾
    
    uint256[47] private __gap; // gap 減 1
}
```

### 真實案例

**Audius ($6M, 2022)**
- 開發者在 proxy 合約中新增了 `proxyAdmin` 變數
- 這個變數與 implementation 中的 `initialized` flag 在同一個 slot
- Proxy 讀 `initialized` 時實際讀到了 `proxyAdmin`（非零地址）
- 因為 `proxyAdmin` 是地址（非零），Solidity 把它當作 false（低位 byte 判斷邏輯錯誤）
- 攻擊者重新調用 `initialize()` → 成為 governor → 竊取 $6M

### 檢測要點
- [ ] 升級前後 storage layout 是否完全相容？（用 `openzeppelin-upgrades` 工具檢查）
- [ ] 是否使用 `__gap` pattern 預留空間？
- [ ] 新變數是否只追加在末尾？
- [ ] Proxy 合約本身是否只使用 EIP-1967 slot？
- [ ] 繼承鏈是否保持一致？
- [ ] 多重繼承的線性化順序是否改變？

---

## 4. Unauthorized Upgrade (Admin Key Compromise)

### 漏洞描述
升級權限是「God mode」— 能升級就能做任何事。如果 admin key 被盜或 `_authorizeUpgrade` 缺少存取控制，攻擊者可以部署惡意 implementation 接管所有資金。

### 攻擊模式
```solidity
// ❌ UUPS 缺少存取控制
contract VaultV1 is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {
        // 沒有 onlyOwner 或任何檢查!
    }
}

// ❌ Transparent proxy admin key 是 EOA
// 如果私鑰被盜，一筆交易就能升級 + 竊取所有資金
```

### 攻擊流程（UPCX 模式）
```
1. 獲取 admin/deployer 私鑰（釣魚、惡意軟體、內部人員）
2. 部署含 withdrawAll() 的惡意 implementation
3. 調用 ProxyAdmin.upgrade(proxy, maliciousImpl)
4. 調用 proxy.withdrawAll() → 資金轉入攻擊者地址
5. 通過混幣器/跨鏈橋逃逸

// 整個過程可以在一筆交易中完成（如果沒有 timelock）
```

### 安全代碼
```solidity
// ✅ UUPS: 嚴格的升級授權
contract VaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyOwner  // ✅ 存取控制
    {
        // ✅ 可加額外驗證
        require(
            IERC1822Proxiable(newImplementation).proxiableUUID() == 
            _IMPLEMENTATION_SLOT,
            "Invalid implementation"
        );
    }
}

// ✅ Admin 架構: Multi-sig + Timelock
// ProxyAdmin → owned by Timelock → owned by Multi-sig (3/5)
// 升級流程:
// 1. Multi-sig 提交 schedule(upgrade, delay=48h)
// 2. 48h 等待期間社區可以審查
// 3. Multi-sig 調用 execute(upgrade)
```

### 真實案例

**UPCX ($70M, April 2025)**
- 攻擊者獲取了特權地址的私鑰
- 升級 ProxyAdmin 合約
- 調用 `withdrawByAdmin()` 函數
- 竊取 18.4M UPC token（價值 $70M）
- 沒有 timelock，沒有多簽，一筆交易完成

**USDGambit/TLP ($1.5M, Jan 2026)**
- 兩個 Arbitrum DeFi 協議共享同一個 deployer
- 攻擊者獲取 deployer 私鑰
- 部署惡意 ProxyAdmin 控制兩個協議
- 資金通過 L2→L1 bridge → Tornado Cash 逃逸

### 檢測要點
- [ ] `_authorizeUpgrade()` 是否有 `onlyOwner` 或等效存取控制？
- [ ] Admin 是 multi-sig 還是 EOA？（EOA = Critical Risk）
- [ ] 是否有 Timelock？Timelock 延遲是否足夠？（≥48h）
- [ ] 是否有升級事件監控和告警？
- [ ] admin key 是否存放在硬體錢包？

---

## 5. UUPS-Specific Vulnerabilities

### 5a. 缺少 onlyProxy Modifier
```solidity
// ❌ upgradeTo 可以直接在 implementation 上調用
contract VaultV1 is UUPSUpgradeable {
    function upgradeTo(address newImpl) external {
        // 缺少 onlyProxy modifier
        // 攻擊者可以直接在 implementation 上調用
        // 雖然只修改 implementation 的 storage，但可能造成混淆
    }
}
```

### 5b. 升級時丟失 UUPS hooks
```solidity
// ❌ V2 忘記繼承 UUPSUpgradeable
contract VaultV2 is OwnableUpgradeable {
    // 沒有 upgradeTo, _authorizeUpgrade, proxiableUUID
    // 可以升級到 V2，但之後再也無法升級!
    // Proxy 永久卡在 V2
}
```

### 5c. proxiableUUID 不一致
```solidity
// ❌ 自定義 proxiableUUID 與 proxy 不匹配
contract VaultV2 is UUPSUpgradeable {
    function proxiableUUID() external pure override returns (bytes32) {
        return keccak256("custom.slot"); // 與 EIP-1967 不匹配!
    }
    // Proxy 會拒絕升級（安全機制），但合約被鎖定
}
```

### 檢測要點
- [ ] 所有 UUPS implementation 是否都繼承 UUPSUpgradeable？
- [ ] `proxiableUUID()` 在所有版本中是否一致？
- [ ] `upgradeTo()` 是否有 `onlyProxy` modifier？
- [ ] 升級路徑是否測試過？（V1→V2→V3 都能成功）

---

## 6. Beacon Proxy Risks

### 漏洞描述
Beacon proxy 讓多個 proxy 共用同一個 implementation。一次 Beacon 升級影響所有 proxy — 放大了升級錯誤的影響範圍。

### 攻擊模式
```solidity
// Beacon 控制 100 個 vault proxy
// 如果 Beacon admin 被攻破:
// 1. 攻擊者升級 Beacon → 惡意 implementation
// 2. 100 個 vault 同時被控制
// 3. 批量竊取所有 vault 的資金

// ❌ Beacon admin 是 EOA
UpgradeableBeacon beacon = new UpgradeableBeacon(implV1, eoaAdmin);
```

### 安全代碼
```solidity
// ✅ Beacon admin = Timelock + Multi-sig
UpgradeableBeacon beacon = new UpgradeableBeacon(implV1, timelockAddress);
// Timelock owned by multi-sig (3/5)
// 升級需要 48h+ 延遲
```

### 檢測要點
- [ ] Beacon admin 是否受 multi-sig + timelock 保護？
- [ ] 是否有「緊急暫停」機制？
- [ ] 單個 Beacon 影響多少個 proxy？（影響範圍評估）
- [ ] 各 proxy 是否需要獨立初始化？

---

## 7. Function Selector Collision

### 漏洞描述
Proxy 和 implementation 共享函數命名空間。如果 implementation 中的函數 selector 與 proxy 的管理函數衝突，可能導致意外行為。

### 攻擊模式
```solidity
// Transparent Proxy 有 admin 函數:
// upgradeTo(address) → selector: 0x3659cfe6

// ❌ Implementation 碰巧有相同 selector 的函數
contract VaultV1 {
    // collate_propagate_storage(bytes16) 的 selector 也是 0x3659cfe6
    function collate_propagate_storage(bytes16) external {
        // 這個函數永遠不會被調用（被 proxy 攔截）
        // 或者更糟：被當作 upgradeTo 執行
    }
}
```

### 檢測要點
- [ ] Implementation 的函數 selector 是否與 proxy 管理函數衝突？
- [ ] 是否使用 OZ 的 TransparentUpgradeableProxy（已內建防護）？
- [ ] Transparent proxy 中 admin 調用是否正確隔離？

---

## 8. delegatecall to Untrusted Address

### 漏洞描述
Implementation 中如果有 `delegatecall` 到任意地址，攻擊者可以讓 proxy 執行任意代碼。

### 攻擊模式
```solidity
// ❌ Implementation 允許 delegatecall 到任意地址
contract VaultV1 {
    function execute(address target, bytes calldata data) external onlyOwner {
        (bool success,) = target.delegatecall(data);
        require(success);
    }
}

// 即使有 onlyOwner:
// 1. 如果 owner 被攻破 → 直接 delegatecall selfdestruct
// 2. 或者 delegatecall 到修改 implementation slot 的合約 → 繞過正常升級流程
```

### 安全代碼
```solidity
// ✅ 只 delegatecall 到已知的、不可變的地址
// ✅ 或者完全避免在 upgradeable 合約中使用 delegatecall
// ✅ 如果必須用，加白名單
mapping(address => bool) public trustedDelegates;

function execute(address target, bytes calldata data) external onlyOwner {
    require(trustedDelegates[target], "Untrusted target");
    (bool success,) = target.delegatecall(data);
    require(success);
}
```

### 檢測要點
- [ ] Implementation 中是否有 `delegatecall`？
- [ ] 目標地址是否受限？
- [ ] 是否有 `selfdestruct` 或 `delegatecall` 在 implementation 中？（Solidity 0.8.24+ selfdestruct 已棄用但仍可用）

---

## 9. Diamond Proxy (EIP-2535) Specific Risks

### 漏洞描述
Diamond proxy 將功能分散到多個 facet 合約。新增 facet 時可能引入 selector 衝突、storage 衝突、或遺漏存取控制。

### 攻擊模式
```solidity
// ❌ 新 facet 的 storage 與現有 facet 衝突
// Diamond 不強制 storage 隔離 — 開發者必須手動管理

// ❌ diamondCut 添加惡意 facet
// 如果 diamond owner 被攻破，可以添加含後門的 facet

// ❌ facet 函數 selector 重複
// 兩個 facet 有相同 selector → 只有一個會被路由
```

### 檢測要點
- [ ] 所有 facet 是否使用 Diamond Storage pattern（命名空間隔離）？
- [ ] `diamondCut` 是否有 multi-sig + timelock 保護？
- [ ] 是否檢查新 facet 的 selector 不與現有 facet 衝突？
- [ ] facet 移除時是否正確清理 storage？

---

## 10. Upgrade Testing & Verification

### 常見測試遺漏

```solidity
// ✅ 升級前必須測試的項目:

// 1. Storage layout 相容性
// forge inspect VaultV1 storage-layout > v1.json
// forge inspect VaultV2 storage-layout > v2.json
// diff v1.json v2.json

// 2. 升級路徑測試
function testUpgradePath() public {
    // Deploy V1
    proxy = deployProxy(VaultV1, [owner]);
    
    // Set state in V1
    VaultV1(proxy).deposit(1 ether);
    
    // Upgrade to V2
    upgradeProxy(proxy, VaultV2);
    
    // Verify state preserved
    assertEq(VaultV2(proxy).totalDeposits(), 1 ether);
    
    // Verify new functionality works
    VaultV2(proxy).initializeV2(newParam);
    assertEq(VaultV2(proxy).newParam(), newParam);
}

// 3. 升級後不能再初始化
function testCannotReinitialize() public {
    upgradeProxy(proxy, VaultV2);
    vm.expectRevert("Initializable: contract is already initialized");
    VaultV2(proxy).initialize(attacker);
}

// 4. 升級鏈完整性
function testUpgradeChain() public {
    // V1 → V2 → V3 都要測試
    // 確保每一步 storage 都正確
}
```

---

## Audit Checklist: Proxy & Upgrade Security

### A. 初始化安全
- [ ] A1: Implementation constructor 調用 `_disableInitializers()`
- [ ] A2: Proxy 在部署同一 tx 中初始化（`deployProxy` / `upgradeToAndCall`）
- [ ] A3: 所有父合約的 `__init()` 都被調用
- [ ] A4: `initializer` / `reinitializer(N)` modifier 正確使用
- [ ] A5: 升級後無法重新初始化

### B. Storage 安全
- [ ] B1: 升級只追加新變數，不重排
- [ ] B2: 使用 `__gap` pattern 預留空間
- [ ] B3: 繼承鏈順序不變
- [ ] B4: Proxy 合約只使用 EIP-1967 slot
- [ ] B5: 使用 OZ upgrades 工具驗證 layout 相容性
- [ ] B6: 多重繼承線性化順序一致

### C. 存取控制
- [ ] C1: UUPS `_authorizeUpgrade` 有 `onlyOwner` 或等效控制
- [ ] C2: Admin 是 multi-sig（≥ 3/5）
- [ ] C3: 有 Timelock（≥ 48h）
- [ ] C4: Admin key 存放在硬體錢包
- [ ] C5: 升級有事件監控和告警

### D. UUPS 特定
- [ ] D1: 每個版本都繼承 `UUPSUpgradeable`
- [ ] D2: `proxiableUUID()` 跨版本一致
- [ ] D3: `upgradeTo` 有 `onlyProxy` modifier
- [ ] D4: 升級路徑 V1→V2→V3→... 完整測試

### E. 通用安全
- [ ] E1: Implementation 中無 `selfdestruct`
- [ ] E2: Implementation 中無任意 `delegatecall`
- [ ] E3: 函數 selector 無衝突
- [ ] E4: Diamond proxy: facet storage 隔離
- [ ] E5: Beacon proxy: admin 受 timelock + multi-sig 保護

### F. 測試 & 驗證
- [ ] F1: Storage layout diff 自動化（CI/CD）
- [ ] F2: 升級 + state preservation 測試
- [ ] F3: 重新初始化防護測試
- [ ] F4: 升級鏈完整性測試
- [ ] F5: Mainnet fork 模擬升級

---

## 案例總覽

| 案例 | 年份 | 損失 | 漏洞類型 | 根因 |
|------|------|------|----------|------|
| Parity Multi-sig | 2017 | $150M frozen | Uninitialized | Library 未初始化 → selfdestruct |
| Wormhole | 2022 | $10M bounty | Uninitialized | 升級後 implementation 未初始化 |
| Audius | 2022 | $6M | Storage collision | Proxy 新增變數覆蓋 initialized flag |
| AllianceBlock | 2024 | Caught early | Re-initialization | 升級重置 initialized flag |
| UPCX | 2025 | $70M | Admin key compromise | EOA admin → ProxyAdmin upgrade → withdrawByAdmin |
| USDGambit/TLP | 2026 | $1.5M | Admin key compromise | 共享 deployer → ProxyAdmin → bridge exit |

---

*建立於 2026-02-13 02:00 AM | 基於 Three Sigma, Octane Security, CertiK, Hacken, Proxion (arXiv:2409.13563), USCSA (arXiv:2412.01719) 研究*
