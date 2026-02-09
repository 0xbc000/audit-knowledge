# ERC721/ERC1155 Callback Security Patterns

> **Source:** Revert Lend Benchmark (Code4rena 2024-03) - 3 findings missed
> **Priority:** HIGH - Commonly exploited in lending/vault protocols

---

## Overview

External callbacks in token transfers (ERC721, ERC1155, ERC777) create reentrancy and DoS vectors. These are especially dangerous in:
- **Lending protocols** - liquidation can be blocked
- **Vaults** - deposit/withdraw manipulation
- **NFT-collateralized protocols** - position manipulation

---

## 1. Liquidation Callback DoS

### Pattern Description
When a protocol uses `safeTransferFrom()` during liquidation, the liquidated user can implement `onERC721Received` that reverts, permanently blocking liquidation.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: User can block liquidation
function liquidate(uint256 tokenId, address owner) external {
    // ... checks ...
    
    // User's callback can revert here!
    nftCollection.safeTransferFrom(address(this), owner, tokenId);
    
    // Cleanup never happens
    _cleanupLoan(tokenId);
}
```

### Attack Scenario
1. Borrower takes loan with NFT collateral
2. Position becomes undercollateralized
3. Borrower deploys malicious receiver contract as new owner
4. Liquidator calls `liquidate()`
5. `safeTransferFrom` → `onERC721Received` → REVERT
6. Liquidation fails permanently, bad debt accumulates

### Detection Questions
- Does liquidation use `safeTransferFrom` for NFTs?
- Can the recipient of liquidated assets be a contract?
- What happens if the recipient reverts in callback?
- Is there a fallback mechanism if transfer fails?

### Secure Patterns
```solidity
// OPTION 1: Use transfer() instead of safeTransferFrom()
// Risk: NFT may be stuck if recipient can't receive

// OPTION 2: Pull pattern - let owner claim later
mapping(uint256 => address) public claimableNFTs;

function liquidate(uint256 tokenId) external {
    address owner = positions[tokenId].owner;
    _cleanupLoan(tokenId);  // Do this FIRST
    claimableNFTs[tokenId] = owner;  // Mark for claim
}

function claimNFT(uint256 tokenId) external {
    require(claimableNFTs[tokenId] == msg.sender);
    delete claimableNFTs[tokenId];
    nftCollection.safeTransferFrom(address(this), msg.sender, tokenId);
}

// OPTION 3: Try-catch with fallback
function liquidate(uint256 tokenId, address owner) external {
    _cleanupLoan(tokenId);
    try nftCollection.safeTransferFrom(address(this), owner, tokenId) {
        // Success
    } catch {
        // Fallback: store for manual claim
        pendingClaims[tokenId] = owner;
    }
}
```

### Real Examples
- **Revert Lend H-06:** Owner prevents liquidation via malicious `onERC721Received`
- **Multiple NFT lending protocols:** Similar patterns found

---

## 2. Callback Reentrancy in State Updates

### Pattern Description
When `safeTransferFrom` is called BEFORE critical state updates, the callback can re-enter and manipulate state.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: CEI violation with callback
function _cleanupLoan(uint256 tokenId) internal {
    Position storage pos = positions[tokenId];
    address owner = pos.owner;
    
    // External call BEFORE state update!
    nftCollection.safeTransferFrom(address(this), owner, tokenId);
    
    // Callback can re-enter before this runs
    _updateAndCheckCollateral(tokenId, 0, pos.collateralAmount);
    delete positions[tokenId];
}
```

### Attack Scenario
1. Attacker borrows against NFT collateral
2. Triggers partial repay or position modification
3. `safeTransferFrom` called in cleanup
4. In `onERC721Received`, attacker:
   - Re-enters to borrow more against same collateral
   - Or manipulates collateral factor
5. State update happens after, but damage done

### Detection Questions
- Is there a `safeTransferFrom` before state updates?
- Can `onERC721Received` callback call back into protocol?
- What state is accessible during the callback?
- Is there a reentrancy guard on all relevant functions?

### Secure Patterns
```solidity
// SECURE: Update state BEFORE external call (CEI pattern)
function _cleanupLoan(uint256 tokenId) internal {
    Position storage pos = positions[tokenId];
    address owner = pos.owner;
    
    // Update ALL state first
    _updateAndCheckCollateral(tokenId, 0, pos.collateralAmount);
    delete positions[tokenId];
    
    // External call LAST
    nftCollection.safeTransferFrom(address(this), owner, tokenId);
}

// Or use reentrancy guard
function _cleanupLoan(uint256 tokenId) internal nonReentrant {
    // ... safe because reentrant calls blocked
}
```

### Real Examples
- **Revert Lend H-02:** Reentrancy via `onERC721Received` to manipulate collateral configs

---

## 3. ERC1155 Batch Callback Exploitation

### Pattern Description
ERC1155 `safeBatchTransferFrom` calls `onERC1155BatchReceived`, which can be exploited for:
- Reentrancy with multiple token types
- Gas griefing via large arrays
- State manipulation during batch processing

### Vulnerable Code Pattern
```solidity
// VULNERABLE: Batch transfer with state dependency
function withdrawAll(uint256[] calldata tokenIds) external {
    for (uint i = 0; i < tokenIds.length; i++) {
        balances[tokenIds[i]][msg.sender] -= amounts[i];
    }
    
    // Single callback at end - but state already modified
    token.safeBatchTransferFrom(address(this), msg.sender, tokenIds, amounts, "");
}
```

### Detection Questions
- Does the protocol use ERC1155 batch transfers?
- What state changes occur during batch processing?
- Can callback affect tokens not yet processed in batch?
- Are gas limits properly enforced?

---

## 4. Gas Griefing via Callbacks

### Pattern Description
Recipient contracts can consume excessive gas in callbacks, causing legitimate transactions to fail.

### Vulnerable Code Pattern
```solidity
// VULNERABLE: No gas limit on callback
function executeAutomation(uint256 tokenId) external {
    // Automation calls safeTransferFrom with no gas limit
    nft.safeTransferFrom(address(this), recipient, tokenId);
}
```

### Attack Scenario
1. Attacker sets up position with malicious receiver
2. Automation bot tries to execute (e.g., rebalance, stop-loss)
3. Callback consumes all gas
4. Transaction reverts, automation fails
5. Position suffers losses due to failed automation

### Detection Questions
- Does the protocol rely on automation/keepers?
- Can recipients be arbitrary contracts?
- Is there gas limit on external calls?
- What happens if automation consistently fails?

### Secure Patterns
```solidity
// Use gas limit on callback
(bool success,) = address(token).call{gas: 100000}(
    abi.encodeWithSelector(
        IERC721.safeTransferFrom.selector,
        address(this),
        recipient,
        tokenId
    )
);

// Or use regular transfer with safety check
function executeAutomation(uint256 tokenId) external {
    if (!_isContract(recipient)) {
        nft.transferFrom(address(this), recipient, tokenId);
    } else {
        pendingTransfers[tokenId] = recipient;  // Let them pull
    }
}
```

---

## 5. ERC777 Hook Exploitation

### Pattern Description
ERC777 tokens have before/after transfer hooks (`tokensToSend`, `tokensReceived`) that can be exploited even without explicit `safeTransfer` calls.

### Key Risks
- Any `transfer()` can trigger callbacks
- Both sender AND receiver can have hooks
- Often forgotten when protocol accepts "any ERC20"

### Detection Questions
- Does the protocol accept arbitrary ERC20 tokens?
- Are ERC777 tokens explicitly blocked?
- Is there reentrancy protection on all token operations?

---

## Checklist: Callback Security Audit

### Transfer Method Analysis
- [ ] Identify all `safeTransferFrom` (ERC721/1155) calls
- [ ] Identify all `safeBatchTransferFrom` calls
- [ ] Identify all ERC777-compatible token transfers
- [ ] Map which functions can trigger callbacks

### State Ordering
- [ ] For each callback-triggering transfer:
  - [ ] What state reads happen before?
  - [ ] What state writes happen before?
  - [ ] What state is accessible during callback?
  - [ ] Is CEI pattern followed?

### DoS Vectors
- [ ] Can liquidations be blocked via callback revert?
- [ ] Can automation/keeper operations be blocked?
- [ ] Can withdraw operations be blocked?
- [ ] Is there fallback for failed transfers?

### Reentrancy
- [ ] Is reentrancy guard applied to all relevant functions?
- [ ] Can callback access same function?
- [ ] Can callback access related functions?
- [ ] Is state consistent during callback?

### Gas Limits
- [ ] Are callbacks gas-limited where appropriate?
- [ ] What happens if callback consumes excessive gas?
- [ ] Can gas griefing affect protocol operations?

---

## Code Patterns to Flag

```solidity
// HIGH PRIORITY - Check all of these:

// 1. safeTransferFrom before state update
nft.safeTransferFrom(a, b, id);
someStateUpdate();  // Should be BEFORE

// 2. safeTransferFrom to user-controlled address in liquidation
function liquidate(uint id) {
    nft.safeTransferFrom(vault, borrower, id);  // DoS risk!
}

// 3. Batch transfer with loop state updates
for (uint i = 0; i < ids.length; i++) {
    processToken(ids[i]);  // State changes
}
token.safeBatchTransferFrom(...);  // Single callback

// 4. No reentrancy guard on callback-sensitive function
function withdraw(uint id) external {  // Missing: nonReentrant
    nft.safeTransferFrom(address(this), msg.sender, id);
}
```

---

*Last Updated: 2026-02-04*
*Source: Revert Lend Benchmark Analysis*
