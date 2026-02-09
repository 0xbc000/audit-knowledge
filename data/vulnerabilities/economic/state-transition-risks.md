# Protocol State Transition Vulnerability Patterns

> **Source:** Revert Lend Benchmark (M-10, M-20), Multiple DeFi Audits
> **Priority:** MEDIUM-HIGH - Often overlooked admin/config edge cases

---

## Overview

DeFi protocols have configurable states that admins can change. Vulnerabilities arise when:
- Users have funds/positions during state transition
- State changes don't account for existing state
- Inverse operations aren't symmetric

---

## 1. Feature Disable with Active Positions

### Pattern Description
When admins disable a feature (vault, market, token), existing users may have funds stuck or be unable to exit.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: No way to exit after deactivation
bool public active = true;

modifier onlyActive() {
    require(active, "Not active");
    _;
}

function setActive(bool _active) external onlyAdmin {
    active = _active;
}

function deposit(uint256 amount) external onlyActive {
    balances[msg.sender] += amount;
    token.transferFrom(msg.sender, address(this), amount);
}

function withdraw(uint256 amount) external onlyActive {  // BUG!
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount);
}
```

### Attack/Impact Scenario
1. Users deposit funds
2. Admin calls `setActive(false)` (emergency, sunset, etc.)
3. Users cannot withdraw - funds stuck forever

### Secure Patterns
```solidity
// OPTION 1: Withdrawals always allowed
function withdraw(uint256 amount) external {  // No modifier
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount);
}

// OPTION 2: Emergency withdraw function
function emergencyWithdraw() external {
    require(!active, "Use normal withdraw");
    uint256 balance = balances[msg.sender];
    balances[msg.sender] = 0;
    token.transfer(msg.sender, balance);
}

// OPTION 3: Sunset period
uint256 public sunsetTimestamp;

function setSunset(uint256 timestamp) external onlyAdmin {
    require(timestamp > block.timestamp + 7 days, "Min 7 day notice");
    sunsetTimestamp = timestamp;
}

function deposit(uint256 amount) external {
    require(sunsetTimestamp == 0 || block.timestamp < sunsetTimestamp);
    // ...
}

function withdraw(uint256 amount) external {
    // Always allowed
}
```

### Detection Questions
- What functions have `onlyActive` or similar modifiers?
- Can users exit when feature is disabled?
- Is there an emergency withdraw?
- What happens to pending operations during disable?

### Real Examples
- **Revert Lend M-10:** Tokens stuck after vault deactivated

---

## 2. Config Removal Without Cleanup

### Pattern Description
When removing a supported token/pool/collateral from config, existing positions using that asset may become orphaned.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: Can't remove token if anyone is using it
mapping(address => bool) public supportedTokens;
mapping(address => mapping(address => uint256)) public collateralBalances; // user => token => amount

function removeToken(address token) external onlyAdmin {
    supportedTokens[token] = false;
    // BUG: What about existing collateral?
}

function withdrawCollateral(address token, uint256 amount) external {
    require(supportedTokens[token], "Token not supported");  // Fails for removed tokens!
    collateralBalances[msg.sender][token] -= amount;
    IERC20(token).transfer(msg.sender, amount);
}
```

### Secure Patterns
```solidity
// OPTION 1: Check for existing usage before removal
function removeToken(address token) external onlyAdmin {
    require(totalCollateral[token] == 0, "Token in use");
    supportedTokens[token] = false;
}

// OPTION 2: Allow withdrawal of removed tokens
function withdrawCollateral(address token, uint256 amount) external {
    // Allow if supported OR user has existing balance
    require(
        supportedTokens[token] || collateralBalances[msg.sender][token] > 0,
        "Invalid token"
    );
    collateralBalances[msg.sender][token] -= amount;
    IERC20(token).transfer(msg.sender, amount);
}

// OPTION 3: Migration function
function migrateRemovedToken(address oldToken, address newToken) external onlyAdmin {
    require(!supportedTokens[oldToken], "Token still active");
    require(supportedTokens[newToken], "New token not supported");
    // ... migrate logic
}
```

### Detection Questions
- What happens when a token/pool is removed from config?
- Can users with existing positions still exit?
- Is there a migration path for removed assets?
- Does removal affect collateral valuation?

### Real Examples
- **Revert Lend M-20:** Can't remove collateral token while positions exist

---

## 3. Asymmetric Add/Remove Operations

### Pattern Description
Adding an entity (token, pool, user) should be inverse of removing. Often the remove operation forgets to clean up associated state.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: Whitelist removal doesn't clear state
mapping(address => bool) public whitelisted;
mapping(address => uint256) public accruedRewards;

function addToWhitelist(address user) external onlyAdmin {
    whitelisted[user] = true;
}

function removeFromWhitelist(address user) external onlyAdmin {
    whitelisted[user] = false;
    // BUG: accruedRewards[user] not cleared
}

function claimRewards() external {
    require(whitelisted[msg.sender], "Not whitelisted");
    uint256 rewards = accruedRewards[msg.sender];
    accruedRewards[msg.sender] = 0;
    rewardsToken.transfer(msg.sender, rewards);
}
```

### Attack Scenario
1. User gets whitelisted, accrues rewards
2. Admin removes from whitelist (unwhitelist)
3. Admin adds user back later (re-whitelist)
4. User claims old accumulated rewards they shouldn't get

### Secure Patterns
```solidity
function removeFromWhitelist(address user) external onlyAdmin {
    whitelisted[user] = false;
    // Clear associated state
    delete accruedRewards[user];
    delete lastUpdateTime[user];
}
```

### Detection Questions
- For every `add` function, is there a corresponding `remove`?
- Does `remove` clean up all associated state?
- What happens if entity is re-added?
- Are there any state leaks between add/remove cycles?

### Real Examples
- **Salty.IO M-10:** Unwhitelisting doesn't clear `_arbitrageProfits`

---

## 4. Pause State Inconsistencies

### Pattern Description
Pausing a protocol should stop risky operations but allow safe exits. Often implemented inconsistently.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: Pause blocks everything including exits
bool public paused;

modifier whenNotPaused() {
    require(!paused, "Paused");
    _;
}

function deposit() external whenNotPaused { ... }
function withdraw() external whenNotPaused { ... }  // Should be allowed!
function borrow() external whenNotPaused { ... }
function repay() external whenNotPaused { ... }  // Should be allowed!
```

### Secure Pattern
```solidity
modifier whenNotPaused() {
    require(!paused, "Paused");
    _;
}

// Risk-increasing operations - pause
function deposit() external whenNotPaused { ... }
function borrow() external whenNotPaused { ... }

// Risk-decreasing operations - always allow
function withdraw() external { ... }
function repay() external { ... }
function liquidate() external { ... }  // Critical for health
```

### Detection Questions
- Which functions are paused?
- Can users reduce risk during pause? (withdraw, repay)
- Can liquidations proceed during pause?
- Is there a time limit on pause?

---

## 5. Parameter Change Without Interest Update

### Pattern Description
Changing protocol parameters (interest rates, fees, factors) should trigger an interest accrual first, or state becomes inconsistent.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: Rate change doesn't update accruals first
uint256 public interestRatePerSecond;
uint256 public lastUpdateTime;
uint256 public totalDebt;

function setInterestRate(uint256 newRate) external onlyAdmin {
    interestRatePerSecond = newRate;  // BUG: Old debt not updated!
}

function accrueInterest() public {
    uint256 timeElapsed = block.timestamp - lastUpdateTime;
    totalDebt += totalDebt * interestRatePerSecond * timeElapsed / 1e18;
    lastUpdateTime = block.timestamp;
}
```

### Attack Scenario
1. Total debt = 1000, rate = 5%
2. 1 year passes without accrual call
3. Admin changes rate to 1%
4. `accrueInterest()` called - calculates: 1000 * 1% * 1 year
5. Borrowers paid only 1% instead of 5%!

### Secure Pattern
```solidity
function setInterestRate(uint256 newRate) external onlyAdmin {
    accrueInterest();  // Update with old rate first
    interestRatePerSecond = newRate;
}
```

### Detection Questions
- Do parameter changes trigger state updates first?
- What state depends on the changed parameter?
- Is there time-dependent state affected?
- Order of operations: update state THEN change param

### Real Examples
- **Revert Lend M-05:** `setReserveFactor` doesn't update interest first

---

## 6. Oracle Change Transition

### Pattern Description
Changing oracle source can cause sudden price jumps that enable exploitation.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: Instant oracle switch
address public oracle;

function setOracle(address newOracle) external onlyAdmin {
    oracle = newOracle;  // Instant switch - price may jump
}
```

### Attack Scenario
1. Current oracle: ETH = $3000
2. New oracle (different calculation): ETH = $3100
3. Attacker front-runs oracle change
4. Borrows max at $3000 valuation
5. Oracle changes, collateral now worth $3100
6. Withdraw extra collateral

### Secure Patterns
```solidity
// OPTION 1: Timelock for oracle changes
address public pendingOracle;
uint256 public oracleChangeTime;

function proposeOracle(address newOracle) external onlyAdmin {
    pendingOracle = newOracle;
    oracleChangeTime = block.timestamp + 2 days;
}

function executeOracleChange() external {
    require(block.timestamp >= oracleChangeTime);
    oracle = pendingOracle;
}

// OPTION 2: Price deviation check
function setOracle(address newOracle) external onlyAdmin {
    uint256 oldPrice = IOracle(oracle).getPrice();
    uint256 newPrice = IOracle(newOracle).getPrice();
    
    uint256 deviation = oldPrice > newPrice 
        ? (oldPrice - newPrice) * 10000 / oldPrice
        : (newPrice - oldPrice) * 10000 / oldPrice;
    
    require(deviation < 500, "Price deviation > 5%");
    oracle = newOracle;
}
```

---

## 7. Upgrade/Migration State Corruption

### Pattern Description
Protocol upgrades or migrations may corrupt state if not handled atomically.

### Vulnerable Pattern
```solidity
// VULNERABLE: Two-step migration with intermediate invalid state
function migrateV1toV2_step1() external onlyAdmin {
    // Disable v1
    v1.pause();
}

function migrateV1toV2_step2() external onlyAdmin {
    // Copy state to v2
    v2.initialize(v1.totalDebt(), v1.totalCollateral());
}

// If step2 fails, protocol is stuck!
```

### Secure Pattern
```solidity
function migrateV1toV2() external onlyAdmin {
    // Atomic migration
    v1.pause();
    
    try v2.initialize(v1.totalDebt(), v1.totalCollateral()) {
        // Success - enable v2
        v2.unpause();
    } catch {
        // Rollback - re-enable v1
        v1.unpause();
        revert("Migration failed");
    }
}
```

---

## Checklist: State Transition Audit

### Feature Enable/Disable
- [ ] List all features that can be enabled/disabled
- [ ] For each: can users exit when disabled?
- [ ] Is there emergency withdraw?
- [ ] What happens to pending operations?

### Token/Entity Management
- [ ] What happens when token is removed?
- [ ] Can users with positions still exit?
- [ ] Is state cleared on removal?
- [ ] What if entity is re-added?

### Parameter Changes
- [ ] Do param changes update dependent state first?
- [ ] Is there timelock on critical parameters?
- [ ] What state is affected by each parameter?
- [ ] Can param changes be sandwiched?

### Pause Functionality
- [ ] Which functions are paused?
- [ ] Can users reduce risk during pause?
- [ ] Are liquidations allowed during pause?
- [ ] Is there max pause duration?

### Upgrades/Migrations
- [ ] Is migration atomic?
- [ ] What happens if migration fails?
- [ ] Is there rollback mechanism?
- [ ] Are there intermediate invalid states?

---

## Code Patterns to Flag

```solidity
// 1. Withdraw blocked when inactive
function withdraw() external onlyActive { ... }  // BUG

// 2. No cleanup on removal
function removeToken(address t) external { supportedTokens[t] = false; }  // Missing state cleanup

// 3. Param change without update
function setRate(uint r) external { rate = r; }  // Should call accrueInterest() first

// 4. Instant oracle switch
function setOracle(address o) external { oracle = o; }  // Should have timelock/checks

// 5. Non-atomic migration
function migrate_step1() external { ... }
function migrate_step2() external { ... }  // Should be single function
```

---

*Last Updated: 2026-02-04*
*Source: Revert Lend Benchmark, Multiple Protocol Audits*
