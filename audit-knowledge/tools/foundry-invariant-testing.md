# Foundry Invariant Testing 指南

## 為什麼重要

Invariant testing 可以自動發現違反業務邏輯的情況：
- 隨機生成交易序列
- 在每次操作後檢查 invariants
- 比手動測試覆蓋更多邊界條件

## 基本設置

### 1. 定義 Invariant 函數

```solidity
// test/invariants/VaultInvariant.t.sol
contract VaultInvariantTest is Test {
    Vault vault;
    
    function setUp() public {
        vault = new Vault();
        // setup...
    }
    
    // Invariant: 總 credit delegation <= 總資產
    function invariant_creditDelegationBounded() public {
        uint256 totalDelegated = vault.getTotalDelegatedCredit();
        uint256 totalAssets = vault.totalAssets();
        
        assertLe(totalDelegated, totalAssets, "Over-delegation detected");
    }
    
    // Invariant: 權重總和正確
    function invariant_weightSumCorrect() public {
        uint256 sumWeights;
        uint256[] memory markets = vault.getConnectedMarkets();
        
        for (uint i = 0; i < markets.length; i++) {
            sumWeights += vault.getCreditDelegationWeight(markets[i]);
        }
        
        assertEq(sumWeights, vault.totalWeight(), "Weight sum mismatch");
    }
}
```

### 2. 定義 Handler（操作生成器）

```solidity
contract VaultHandler is Test {
    Vault vault;
    
    constructor(Vault _vault) {
        vault = _vault;
    }
    
    // Foundry 會隨機調用這些函數
    function deposit(uint256 amount) public {
        amount = bound(amount, 1, 1e24);
        vault.deposit(amount);
    }
    
    function withdraw(uint256 amount) public {
        amount = bound(amount, 1, vault.maxWithdraw());
        vault.withdraw(amount);
    }
    
    function connectMarket(uint256 marketId) public {
        marketId = bound(marketId, 1, 100);
        vault.connectMarket(marketId);
    }
}
```

### 3. 配置 Invariant Test

```solidity
contract VaultInvariantTest is Test {
    Vault vault;
    VaultHandler handler;
    
    function setUp() public {
        vault = new Vault();
        handler = new VaultHandler(vault);
        
        // 告訴 Foundry 只調用 handler 的函數
        targetContract(address(handler));
    }
    
    // invariant 函數...
}
```

### 4. 運行

```bash
forge test --match-contract VaultInvariantTest -vvv
```

## 配置選項

在 `foundry.toml`:

```toml
[invariant]
runs = 256           # 運行次數
depth = 128          # 每次運行的操作數量
fail_on_revert = false
```

## Zaros 案例應用

### 測試權重分配 Bug

```solidity
function invariant_noDuplicateWeightAllocation() public {
    uint256[] memory markets = vault.getConnectedMarkets();
    uint256 totalAssets = vault.totalAssets();
    uint256 sumAllocations;
    
    for (uint i = 0; i < markets.length; i++) {
        sumAllocations += vault.getCreditDelegationValue(markets[i]);
    }
    
    // 所有分配總和不應超過總資產
    assertLe(sumAllocations, totalAssets, "Over-allocation!");
    
    // 如果有 bug（每個 market 都拿 100%），這個會 fail
}
```

### 測試結算方向

```solidity
function invariant_settlementReducesDebt() public {
    int256 debtBefore = vault.getTotalDebt();
    
    // 觸發結算
    vault.settleDebts();
    
    int256 debtAfter = vault.getTotalDebt();
    
    // 結算後債務應該減少或不變
    assertLe(debtAfter, debtBefore, "Debt increased after settlement!");
}
```

## 技巧

### 1. 使用 Ghost Variables 追蹤狀態

```solidity
contract Handler {
    uint256 public ghost_totalDeposits;
    uint256 public ghost_totalWithdrawals;
    
    function deposit(uint256 amount) public {
        vault.deposit(amount);
        ghost_totalDeposits += amount;
    }
}
```

### 2. 限制搜索空間

```solidity
function deposit(uint256 amount) public {
    // 限制合理範圍，避免無意義的測試
    amount = bound(amount, 1e18, 1e24);
}
```

### 3. 排除已知會 revert 的路徑

```solidity
function withdraw(uint256 amount) public {
    uint256 maxAmount = vault.maxWithdraw();
    if (maxAmount == 0) return;  // 跳過無效操作
    
    amount = bound(amount, 1, maxAmount);
    vault.withdraw(amount);
}
```

## 參考資源

- [Foundry Book - Invariant Testing](https://book.getfoundry.sh/forge/invariant-testing)
- [Trail of Bits - Invariant Testing Guide](https://blog.trailofbits.com/)
