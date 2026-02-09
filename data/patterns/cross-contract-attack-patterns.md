# Cross-Contract Attack Patterns

Source: Compiled from real audit findings
Last Updated: 2026-02-03

These patterns focus on **vulnerabilities that emerge from interactions between contracts**, including reentrancy, callback exploits, and state inconsistencies across call boundaries.

---

## 1. Reentrancy Variants

### 1.1 Classic Reentrancy (ETH Transfer)
**Pattern:** State update after external call

```solidity
// CLASSIC BUG
function withdraw() external {
  uint256 amount = balances[msg.sender];
  (bool success,) = msg.sender.call{value: amount}("");  // Re-entrant!
  balances[msg.sender] = 0;  // Too late
}
```

**Detection:** Look for `.call{}` or `.transfer()` before state updates

---

### 1.2 Read-Only Reentrancy
**Pattern:** View function returns stale state during callback

```solidity
// Contract A - During callback, state is inconsistent
function deposit() external payable {
  totalDeposits += msg.value;  // Updated
  poolToken.mint(msg.sender, shares);  // Callback opportunity
  // lastUpdateTime not yet updated!
}

// Contract B reads inconsistent state
function getPrice() external view returns (uint256) {
  return ContractA.totalDeposits / ContractA.totalShares;
}
```

**Impact:** Price oracles, lending protocols using the stale view

---

### 1.3 Cross-Function Reentrancy
**Pattern:** Reenter through a different function

```solidity
// Function A has reentrancy guard
function withdraw() external nonReentrant { ... }

// Function B doesn't - can be called during A's callback
function borrow() external {  // No guard!
  require(balances[msg.sender] > 0);  // Still has old balance during A
}
```

---

### 1.4 Cross-Contract Reentrancy
**Pattern:** Reenter ContractA via ContractB

```solidity
// ContractA calls ContractB
function processPayment(address token) external {
  IToken(token).transfer(recipient, amount);  // ContractB callback
  // ContractB re-enters ContractA through different path
}
```

---

### 1.5 ERC777/ERC1155 Callback Reentrancy
**Pattern:** Token standards with mandatory callbacks

```solidity
// ERC777 tokensReceived() or ERC1155 onERC1155Received()
function deposit(uint256 amount) external {
  token.safeTransferFrom(msg.sender, address(this), amount);
  // If token is ERC777 -> tokensToSend callback before transfer
  // If token is ERC1155 -> onERC1155Received callback after transfer
  balances[msg.sender] += amount;  // May be too late
}
```

---

## 2. Flash Loan Attack Patterns

### 2.1 Collateral Inflation
**Pattern:** Flash borrow, inflate collateral, borrow against it

```solidity
// Flash loan tokens
// Deposit as collateral (temporarily inflated)
// Borrow maximum against inflated collateral
// Repay flash loan
// Keep borrowed funds, leave bad debt
```

---

### 2.2 Governance Manipulation
**Pattern:** Flash borrow governance tokens

```solidity
// Flash borrow governance tokens
// Vote on malicious proposal (or create one)
// Return tokens
// Proposal passes with flash loan voting power
```

---

### 2.3 Oracle Manipulation
**Pattern:** Flash swap to move spot price

```solidity
// Flash borrow massive amount
// Swap to manipulate AMM spot price
// Execute operation using manipulated price
// Swap back, repay flash loan
// Profit from price discrepancy
```

---

## 3. Callback Attack Patterns

### 3.1 Uniswap V3 Callback Exploitation
**Pattern:** Callback called with attacker-controlled params

```solidity
// UniswapV3 calls your callback
function uniswapV3SwapCallback(
  int256 amount0Delta,
  int256 amount1Delta,
  bytes calldata data
) external {
  // MUST verify: msg.sender is legitimate pool!
  // Attack: Anyone can call this with fake data
}
```

---

### 3.2 Lending Callback Manipulation
**Pattern:** Flashloan callback used for state manipulation

```solidity
function flashLoan(uint256 amount, bytes calldata data) {
  token.transfer(msg.sender, amount);
  IFlashBorrower(msg.sender).onFlashLoan(amount, data);
  // During callback, borrower has tokens + any prior holdings
  // Can manipulate any token-gated logic
}
```

---

### 3.3 Approval Callback Attack
**Pattern:** ERC20 approve triggers callback in some tokens

```solidity
// Some tokens (ERC677, ERC223) have transfer callbacks
// If approval triggers callback, attacker can re-enter
token.approve(spender, amount);
// Attacker's callback runs here
```

---

## 4. State Inconsistency Patterns

### 4.1 Partial Update Before External Call
**Pattern:** Some state updated, then external call, then more updates

```solidity
function processDeposit() external {
  totalSupply += shares;  // State 1 updated
  token.transferFrom(...);  // External call - callback possible
  userShares[msg.sender] += shares;  // State 2 updated
  // During callback: totalSupply updated but userShares not!
}
```

---

### 4.2 Cached Value Divergence
**Pattern:** Cached value becomes stale during call

```solidity
function harvest() external {
  uint256 balance = token.balanceOf(address(this));  // Cached
  strategy.withdraw();  // May change balance via callback
  uint256 profit = token.balanceOf(address(this)) - balance;  // Wrong!
}
```

---

### 4.3 Assumption of Atomicity
**Pattern:** Assumes operations are atomic when they're not

```solidity
// Assumes no one can act between these lines
totalAssets += amount;
// CALLBACK OPPORTUNITY HERE
shares = (amount * totalSupply) / totalAssets;  // Manipulated totalAssets
```

---

## 5. External Call Return Value Issues

### 5.1 Unchecked Return Value
**Pattern:** Ignoring transfer return value

```solidity
// DANGEROUS: Return value ignored!
token.transfer(recipient, amount);  // Some tokens return false instead of reverting

// SAFE:
require(token.transfer(recipient, amount), "Transfer failed");
// Or use SafeERC20:
token.safeTransfer(recipient, amount);
```

---

### 5.2 Unexpected Revert Handling
**Pattern:** Assuming external call always succeeds

```solidity
// If external call reverts, entire transaction reverts
// Attacker can grief by making calls revert
function distributeRewards(address[] calldata users) {
  for (uint i; i < users.length; i++) {
    token.transfer(users[i], reward);  // One revert blocks all
  }
}
```

---

### 5.3 Revert Reason Parsing
**Pattern:** Custom error handling reveals info or fails

```solidity
try external.call() {
  // success
} catch Error(string memory reason) {
  // Only catches require() strings
} catch {
  // Catches custom errors, out of gas, etc.
  // But loses error information
}
```

---

## 6. Composability Attack Patterns

### 6.1 Sandwich via Composable Protocols
**Pattern:** Front-run across multiple protocols

```solidity
// Victim's transaction:
// 1. Swap on Uniswap
// 2. Deposit on Compound
// 3. Stake on Lido

// Attacker:
// Front-run step 1 (sandwich the swap)
// Don't need to interfere with 2, 3
```

---

### 6.2 Cross-Protocol State Dependency
**Pattern:** Protocol A's state depends on Protocol B

```solidity
// Protocol A uses Protocol B for pricing
function getAssetPrice() returns (uint256) {
  return ProtocolB.getPrice(asset);
}

// If Protocol B is manipulated, Protocol A is compromised
```

---

### 6.3 Composable Position Manipulation
**Pattern:** Position on Protocol A affects Protocol B

```solidity
// User has:
// - Collateral on Aave
// - Borrowed funds used on Uniswap LP
// - LP tokens staked on Convex

// Manipulating any layer affects others
// Flash loan through entire stack possible
```

---

## 7. External Protocol Integration Risks

### 7.1 Hardcoded External Addresses
**Pattern:** Assuming external protocol never changes

```solidity
// DANGEROUS: What if Uniswap migrates?
address constant UNISWAP_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

// BETTER: Updateable with timelock
address public uniswapRouter;
function setRouter(address _router) external onlyOwner timelocked { ... }
```

---

### 7.2 Assuming External Protocol Invariants
**Pattern:** Trusting that external protocol behaves as expected

```solidity
// Assuming Chainlink always returns fresh price
(, int256 price,,,) = priceFeed.latestRoundData();
// What if price is stale? What if negative? What if sequencer down?

// NEED: Staleness check, sequencer check, bounds check
```

---

### 7.3 Fee-on-Transfer Token Handling
**Pattern:** Not accounting for transfer fees

```solidity
function deposit(uint256 amount) {
  token.transferFrom(msg.sender, address(this), amount);
  balances[msg.sender] += amount;  // WRONG for fee tokens!
  // Actual received may be less than `amount`
}

// CORRECT:
uint256 before = token.balanceOf(address(this));
token.transferFrom(msg.sender, address(this), amount);
uint256 received = token.balanceOf(address(this)) - before;
balances[msg.sender] += received;
```

---

### 7.4 Rebasing Token Handling
**Pattern:** Not accounting for automatic balance changes

```solidity
// For tokens like stETH that rebase:
balances[user] = stETH.balanceOf(address(this));  // Stored value
// Later: stETH rebases, balanceOf changed
// User's share calculation now wrong
```

---

## Detection Checklist

### Reentrancy
- [ ] Are state updates done before external calls?
- [ ] Does nonReentrant modifier cover all entry points?
- [ ] Are view functions safe during callbacks?
- [ ] Are ERC777/ERC1155 tokens supported safely?

### Flash Loans
- [ ] Can collateral be inflated via flash loan?
- [ ] Can governance be manipulated via flash loan?
- [ ] Can price oracles be manipulated via flash loan?

### Callbacks
- [ ] Are callback callers verified (msg.sender check)?
- [ ] Is state consistent when callbacks execute?
- [ ] Are approval callbacks considered?

### External Calls
- [ ] Are return values checked?
- [ ] Is failure handled gracefully?
- [ ] Are fee-on-transfer tokens handled?
- [ ] Are rebasing tokens handled?

### Composability
- [ ] What external protocols are integrated?
- [ ] What happens if they're manipulated?
- [ ] Are addresses upgradeable?
- [ ] Are external invariants validated?

---

## Prompt Enhancement for AI Auditors

When auditing cross-contract interactions, specifically check:

```
1. State updates after external calls (reentrancy)
2. View functions returning inconsistent state during callbacks
3. Cross-function reentrancy (different function, no guard)
4. Flash loan paths to inflate collateral or voting power
5. Callback functions without msg.sender validation
6. Unchecked return values on token transfers
7. Fee-on-transfer token handling (check balance diff)
8. Rebasing token balance assumptions
9. Hardcoded external protocol addresses
10. External oracle staleness/manipulation
11. Partial state updates before external calls
12. Cached values that can diverge during external calls
```
