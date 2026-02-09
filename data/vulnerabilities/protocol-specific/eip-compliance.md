# EIP/ERC Compliance Vulnerability Patterns

> **Source:** Revert Lend Benchmark (M-14), Multiple DeFi Audits
> **Priority:** MEDIUM - Standard compliance enables composability

---

## Overview

Claiming EIP/ERC compliance but deviating from specs causes:
- Integration failures with other protocols
- Unexpected behavior for users familiar with standard
- Security vulnerabilities when integrators assume compliance

---

## 1. ERC-4626 Vault Compliance Issues

### Standard Requirements
ERC-4626 specifies exact behavior for tokenized vaults:
- `deposit`, `mint`, `withdraw`, `redeem` semantics
- `maxDeposit`, `maxMint`, `maxWithdraw`, `maxRedeem` limits
- `convertToShares`, `convertToAssets` preview functions
- `totalAssets` returns total assets managed

### Common Violations

#### A. Incorrect maxDeposit/maxMint
```solidity
// VULNERABLE: Doesn't account for actual limits
function maxDeposit(address) public view returns (uint256) {
    return type(uint256).max;  // BUG: May not reflect actual capacity
}

// CORRECT:
function maxDeposit(address owner) public view returns (uint256) {
    if (paused) return 0;
    uint256 cap = depositCap;
    uint256 current = totalAssets();
    return cap > current ? cap - current : 0;
}
```

#### B. Preview Functions Don't Match Actual
```solidity
// VULNERABLE: Preview doesn't match reality
function previewDeposit(uint256 assets) public view returns (uint256 shares) {
    return convertToShares(assets);
}

function deposit(uint256 assets) public returns (uint256 shares) {
    shares = convertToShares(assets);
    shares = shares - fee;  // BUG: Fee not in preview!
}

// CORRECT: Preview must return exact same result as execution
function previewDeposit(uint256 assets) public view returns (uint256 shares) {
    shares = convertToShares(assets);
    shares = shares - calculateFee(shares);  // Include fee
}
```

#### C. TotalAssets Doesn't Include All Assets
```solidity
// VULNERABLE: Missing components
function totalAssets() public view returns (uint256) {
    return asset.balanceOf(address(this));
    // BUG: Missing staked assets, accrued interest, etc.
}

// CORRECT:
function totalAssets() public view returns (uint256) {
    return asset.balanceOf(address(this)) 
        + stakedInStrategy 
        + accruedInterest 
        - pendingWithdrawals;
}
```

#### D. Rounding Direction
ERC-4626 specifies rounding direction:
- `convertToShares`, `previewDeposit`, `previewMint`: round DOWN (favor vault)
- `convertToAssets`, `previewWithdraw`, `previewRedeem`: round DOWN (favor vault)

```solidity
// VULNERABLE: Wrong rounding
function convertToShares(uint256 assets) public view returns (uint256) {
    return (assets * totalSupply() + totalAssets() - 1) / totalAssets(); // Rounds UP
}

// CORRECT: Round down
function convertToShares(uint256 assets) public view returns (uint256) {
    return assets * totalSupply() / totalAssets();  // Rounds down
}
```

### Detection Questions
- Does the protocol claim ERC-4626 compliance?
- Do preview functions exactly match execution?
- Is rounding direction correct per spec?
- Does totalAssets include all managed assets?
- Do max* functions reflect actual limits?

### Real Examples
- **Revert Lend M-14:** Not ERC-4626 compliant

---

## 2. ERC-20 Compliance Issues

### Common Violations

#### A. Missing Return Values
Some tokens don't return bool from `transfer`/`transferFrom`.

```solidity
// VULNERABLE: Assumes return value
function pay(address to, uint256 amount) external {
    bool success = token.transfer(to, amount);
    require(success, "Transfer failed");
}

// CORRECT: Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

function pay(address to, uint256 amount) external {
    token.safeTransfer(to, amount);
}
```

#### B. Fee-on-Transfer Tokens
```solidity
// VULNERABLE: Assumes full amount received
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // May be more than received!
}

// CORRECT: Check actual balance change
function deposit(uint256 amount) external {
    uint256 before = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before;
    balances[msg.sender] += received;
}
```

#### C. Rebasing Tokens
```solidity
// VULNERABLE: Assumes balance doesn't change
mapping(address => uint256) public deposits;

function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    deposits[msg.sender] = amount;
}

function withdraw() external {
    uint256 amount = deposits[msg.sender];
    // For rebasing tokens, actual balance may be different!
    token.transfer(msg.sender, amount);
}
```

#### D. Zero Amount Transfers
Some tokens revert on zero transfers.

```solidity
// VULNERABLE: May revert on zero
function withdrawAll(address user) external {
    uint256 amount = balances[user];
    // If amount == 0 and token reverts on zero transfer...
    token.transfer(user, amount);
}

// CORRECT:
function withdrawAll(address user) external {
    uint256 amount = balances[user];
    if (amount > 0) {
        token.transfer(user, amount);
    }
}
```

---

## 3. ERC-721 Compliance Issues

### Common Violations

#### A. Safe Transfer Not Implemented Correctly
```solidity
// VULNERABLE: Doesn't check receiver
function safeTransferFrom(address from, address to, uint256 id) public {
    transferFrom(from, to, id);
    // Missing: onERC721Received check for contracts!
}

// CORRECT:
function safeTransferFrom(address from, address to, uint256 id) public {
    transferFrom(from, to, id);
    if (to.code.length > 0) {
        require(
            IERC721Receiver(to).onERC721Received(msg.sender, from, id, "") 
                == IERC721Receiver.onERC721Received.selector,
            "Not ERC721Receiver"
        );
    }
}
```

#### B. Approval Race Condition
```solidity
// Note: ERC-721 approvals are safer than ERC-20 because they're per-token,
// but getApproved should clear on transfer:

function transferFrom(address from, address to, uint256 id) public {
    require(msg.sender == ownerOf(id) || isApprovedForAll(from, msg.sender) 
            || getApproved(id) == msg.sender);
    _owners[id] = to;
    // Must clear approval!
    delete _tokenApprovals[id];
}
```

---

## 4. ERC-1155 Compliance Issues

### Common Violations

#### A. Batch Balance Check
```solidity
// VULNERABLE: Loops may have different lengths
function balanceOfBatch(
    address[] memory accounts,
    uint256[] memory ids
) public view returns (uint256[] memory) {
    // Must check lengths match!
    require(accounts.length == ids.length, "Length mismatch");
    // ...
}
```

#### B. Safe Transfer Checks
```solidity
// VULNERABLE: Missing receiver check
function safeTransferFrom(
    address from, address to, uint256 id, uint256 amount, bytes memory data
) public {
    _balances[id][from] -= amount;
    _balances[id][to] += amount;
    // Missing: onERC1155Received check!
}
```

---

## 5. ERC-2612 Permit Compliance Issues

### Common Violations

#### A. Permit with Wrong Token
```solidity
// VULNERABLE: Doesn't verify token in permit
function depositWithPermit(
    uint256 amount,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s,
    address token  // User-provided!
) external {
    IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s);
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    // BUG: User can permit wrong token!
}

// CORRECT:
function depositWithPermit(
    uint256 amount,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    // Use known asset address
    IERC20Permit(asset).permit(msg.sender, address(this), amount, deadline, v, r, s);
    asset.transferFrom(msg.sender, address(this), amount);
}
```

#### B. Silent Permit Failure
```solidity
// VULNERABLE: Swallows permit failure
function depositWithPermit(...) external {
    try IERC20Permit(asset).permit(...) {
        // Permit succeeded
    } catch {
        // Silently continues - existing approval may be used
        // Attacker can front-run with their own approval!
    }
    asset.transferFrom(msg.sender, address(this), amount);
}
```

---

## 6. Interface Detection (ERC-165)

### Common Issues
```solidity
// VULNERABLE: Hardcoded interface check
if (IERC165(token).supportsInterface(type(IERC721).interfaceId)) {
    // Assumes all NFTs implement ERC-165
}

// CORRECT: Check if implements ERC-165 first
function supportsERC721(address token) internal view returns (bool) {
    try IERC165(token).supportsInterface(type(IERC165).interfaceId) returns (bool supported165) {
        if (!supported165) return false;
        return IERC165(token).supportsInterface(type(IERC721).interfaceId);
    } catch {
        return false;
    }
}
```

---

## Compliance Checklist

### ERC-4626 Vault
- [ ] `maxDeposit`/`maxMint` reflect actual limits
- [ ] `maxWithdraw`/`maxRedeem` reflect actual limits
- [ ] Preview functions exactly match execution
- [ ] Rounding favors the vault (down for deposits, down for withdrawals in shares)
- [ ] `totalAssets` includes all managed assets
- [ ] Events emitted correctly

### ERC-20 Token
- [ ] Using SafeERC20 for external tokens
- [ ] Handling fee-on-transfer tokens
- [ ] Handling rebasing tokens (if applicable)
- [ ] Handling zero amount transfers
- [ ] Handling tokens without return values

### ERC-721 NFT
- [ ] `safeTransferFrom` checks `onERC721Received`
- [ ] Approvals cleared on transfer
- [ ] `balanceOf(address(0))` reverts
- [ ] `ownerOf` reverts for invalid token

### ERC-2612 Permit
- [ ] Permit token address validated
- [ ] Permit failures not silently swallowed
- [ ] Deadline checked properly
- [ ] Nonce incremented correctly

---

## Code Patterns to Flag

```solidity
// 1. maxDeposit returns type(uint256).max
function maxDeposit(address) public pure returns (uint256) {
    return type(uint256).max;  // Suspicious - check actual limits
}

// 2. Preview doesn't match execution
function previewDeposit(uint256 assets) public view returns (uint256) {
    return convertToShares(assets);  // Check if deposit() does same
}

// 3. User-controlled permit token
function depositWithPermit(..., address token) external {
    IERC20Permit(token).permit(...);  // Should be hardcoded asset

// 4. No SafeERC20
token.transfer(to, amount);  // Should use safeTransfer

// 5. Assumes full amount received
token.transferFrom(msg.sender, address(this), amount);
balances[msg.sender] += amount;  // Check actual received
```

---

*Last Updated: 2026-02-04*
*Source: EIP Standards, Revert Lend Benchmark*
