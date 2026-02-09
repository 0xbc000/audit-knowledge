# Privilege Escalation Patterns

Source: Compiled from real audit findings
Last Updated: 2026-02-03

These patterns focus on **access control bypasses** and **privilege escalation** vulnerabilities.

---

## 1. Direct Access Control Bypasses

### 1.1 Missing Access Control on Critical Functions
**Pattern:** Function lacks `onlyOwner`/`onlyRole` modifier

```solidity
// DANGEROUS: No access control!
function setFeeRecipient(address newRecipient) external {
  feeRecipient = newRecipient;  // Anyone can change
}
```

**Detection:** Look for state-changing functions without modifiers

---

### 1.2 Incorrect Modifier Logic
**Pattern:** Modifier doesn't actually restrict access

```solidity
// BROKEN: Returns true for everyone!
modifier onlyAdmin() {
  if (msg.sender == admin) {
    _;
  }
  _;  // <-- Executes for non-admin too!
}
```

**Detection:** Trace modifier logic for all paths

---

### 1.3 Default Admin on Initialization
**Pattern:** Admin role granted to `address(0)` or wrong address

```solidity
// DANGEROUS: Zero address or msg.sender might be unexpected
function initialize() external {
  _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);  // Who deploys?
}
```

---

## 2. Delegatecall Vulnerabilities

### 2.1 Untrusted Delegatecall Target
**Pattern:** User-controlled delegatecall destination

```solidity
// CRITICAL: User controls target!
function execute(address target, bytes calldata data) external {
  target.delegatecall(data);  // Runs in our storage context
}
```

**Impact:** Complete protocol takeover (storage manipulation)

---

### 2.2 Storage Collision via Delegatecall
**Pattern:** Implementation upgrade with incompatible storage

```solidity
// Old implementation: slot 0 = owner
// New implementation: slot 0 = something else
// Delegatecall reads wrong value for "owner"
```

---

### 2.3 Implementation Self-Destruct
**Pattern:** Implementation contract can be destroyed

```solidity
// If implementation has selfdestruct and it's called...
// Proxy becomes permanently bricked
function kill() external onlyOwner {
  selfdestruct(payable(msg.sender));
}
```

---

## 3. Proxy/Upgrade Vulnerabilities

### 3.1 Unprotected Initialize
**Pattern:** `initialize()` can be called multiple times or by anyone

```solidity
// DANGEROUS: No initializer guard!
function initialize(address _owner) external {
  owner = _owner;  // Can be called repeatedly
}

// Also dangerous: initializer doesn't restrict caller
function initialize() external initializer {
  _grantRole(ADMIN, msg.sender);  // Who is msg.sender?
}
```

---

### 3.2 Upgrade Function Without Timelock
**Pattern:** Immediate upgrade capability

```solidity
// Owner can rug instantly
function upgradeTo(address newImpl) external onlyOwner {
  _implementation = newImpl;  // No delay, no multisig
}
```

---

### 3.3 UUPS Missing Authorization
**Pattern:** `_authorizeUpgrade` not properly restricted

```solidity
// DANGEROUS: Empty authorization!
function _authorizeUpgrade(address) internal override {
  // Missing: require(hasRole(UPGRADER_ROLE, msg.sender))
}
```

---

## 4. Callback/Hook Exploitation

### 4.1 ERC777 Callback Privilege Escalation
**Pattern:** Receiver callback can perform privileged actions

```solidity
// Protocol uses ERC777 tokens
function deposit(uint256 amount) external {
  _updateUserState(msg.sender);  // State updated
  token.transferFrom(...);  // Callback to msg.sender
  // Callback re-enters with elevated state
}
```

---

### 4.2 Flash Loan Callback Privilege
**Pattern:** During flash loan, temporary elevated privileges

```solidity
// Flash loan gives user token balance temporarily
function flashLoan(amount, receiver, data) {
  token.transfer(receiver, amount);
  receiver.onFlashLoan(...);  // Receiver has tokens now
  // Receiver might use tokens for governance voting
}
```

---

## 5. Role/Permission Issues

### 5.1 Role Hierarchy Confusion
**Pattern:** Admin can't revoke certain roles

```solidity
// Role hierarchy misconfiguration
// DEFAULT_ADMIN_ROLE should be admin of all roles
// But SUPER_ROLE has no admin set -> irrevocable
_setRoleAdmin(SUPER_ROLE, bytes32(0));
```

---

### 5.2 Privilege Accumulation
**Pattern:** User gains permanent privileges

```solidity
// Lending protocol: User becomes liquidator
// Problem: Liquidator status never revoked
mapping(address => bool) isLiquidator;

function allowLiquidation(address user) external {
  isLiquidator[user] = true;  // Never set to false
}
```

---

### 5.3 Timelock Bypass via Direct Calls
**Pattern:** Timelocked function can be called directly

```solidity
// setAdmin should go through timelock
function setAdmin(address newAdmin) external {
  // Missing: require(msg.sender == timelock)
  admin = newAdmin;  // Can be called directly!
}
```

---

## 6. Signature/Permit Exploits

### 6.1 Missing Signature Validation
**Pattern:** Signature not verified or replayable

```solidity
// DANGEROUS: No nonce check!
function executeWithSignature(bytes memory sig, bytes memory data) {
  address signer = recover(keccak256(data), sig);
  require(signer == admin);
  // data can be replayed!
}
```

---

### 6.2 Signature Replay Cross-Chain
**Pattern:** Same signature valid on multiple chains

```solidity
// Missing chain ID in signed message
bytes32 hash = keccak256(abi.encodePacked(
  action, nonce, deadline
  // MISSING: block.chainid
));
```

---

### 6.3 Empty Permit with Prior Approval
**Pattern:** Permit silently fails if approval exists

```solidity
// If user has prior approval, permit may be unnecessary
try token.permit(...) {} catch {}
// Attack: Use old approval, bypass permit nonce tracking
```

---

## 7. Governance Attacks

### 7.1 Flash Loan Voting
**Pattern:** Voting power from borrowed tokens

```solidity
// Get massive voting power via flash loan
flashLoan.execute(hugeAmount, this, abi.encode(proposalId));

function onFlashLoan(...) {
  governance.vote(proposalId, voteFor);  // Vote with borrowed power
  // Repay flash loan
}
```

---

### 7.2 Proposal Griefing
**Pattern:** Cheap to create proposals, expensive to vote

```solidity
// Low threshold to propose
function propose(...) external {
  require(votingPower(msg.sender) >= 1000);  // Low bar
}

// Create spam proposals to distract voters
```

---

### 7.3 Short Voting Period + Timelock Manipulation
**Pattern:** Not enough time to react to malicious proposals

```solidity
// 24-hour voting + 48-hour timelock
// Malicious proposal passes over weekend
// Executed before community can respond
```

---

## 8. Emergency/Pause Mechanism Abuse

### 8.1 Unprotected Pause
**Pattern:** Anyone can pause protocol

```solidity
// DANGEROUS: No access control!
function pause() external {
  _pause();  // DoS the entire protocol
}
```

---

### 8.2 No Unpause Mechanism
**Pattern:** Once paused, can't recover

```solidity
function pause() external onlyOwner {
  paused = true;
}
// Missing: unpause() function!
```

---

### 8.3 Pause Doesn't Block Withdrawals
**Pattern:** Pause prevents deposits but not withdrawals

```solidity
function deposit() external whenNotPaused { ... }
function withdraw() external whenNotPaused { ... }  // Should allow!
// Users should be able to exit during emergencies
```

---

## Detection Checklist

### Access Control
- [ ] Does every state-changing function have appropriate access control?
- [ ] Are modifiers correctly implemented (check all code paths)?
- [ ] Is initialization properly protected?

### Upgrade/Proxy
- [ ] Can `initialize()` be called by attacker?
- [ ] Is upgrade function protected and timelocked?
- [ ] Is UUPS `_authorizeUpgrade` properly restricted?

### Delegatecall
- [ ] Are delegatecall targets trusted/immutable?
- [ ] Is storage layout preserved across implementations?
- [ ] Can implementation be destroyed?

### Roles/Permissions
- [ ] Is role hierarchy correctly configured?
- [ ] Can roles be properly revoked?
- [ ] Is there privilege accumulation over time?

### Signatures
- [ ] Is there nonce tracking?
- [ ] Is chain ID included in signed message?
- [ ] Are permit failures handled correctly?

### Governance
- [ ] Is flash loan voting possible?
- [ ] Is voting period sufficient for community response?
- [ ] Are proposal thresholds reasonable?

---

## Prompt Enhancement for AI Auditors

When auditing for privilege escalation, specifically check:

```
1. State-changing functions without access control modifiers
2. Modifiers with fallthrough paths (missing return/revert)
3. initialize() callable by anyone or multiple times
4. User-controlled delegatecall targets
5. UUPS _authorizeUpgrade without role check
6. Signatures without nonce or chain ID
7. Flash loan compatible with governance voting
8. Pause/unpause asymmetry (can't exit during pause)
9. Role admin misconfiguration (irrevocable roles)
10. Timelock bypass via direct function calls
```
