# External Integration Risk Patterns

Vulnerabilities arising from dependencies on external protocols, tokens, and services.

---

## 1. External Protocol Assumptions

### 1.1 Behavior Assumption Violations
**Description:** Assuming external protocol behaves in specific way
**From Napier 015-H:**
```solidity
// VULNERABLE: Hardcoded assumption
// Assumes 1 Curve LP token = 3 PT always
// Only true at perfectly balanced initial deposit
uint256 ptValue = lpAmount * 3;

// SAFER: Query actual value
uint256 ptValue = curvePool.calc_withdraw_one_coin(lpAmount, PT_INDEX);
```

**Detection Pattern:**
- Are there hardcoded ratios for external tokens?
- Are assumptions documented?
- Have assumptions been validated?

### 1.2 Interface Changes
**Description:** External protocol upgrades and changes interface
**Detection Pattern:**
- Are external calls to upgradeable contracts?
- What happens if function signatures change?
- Are return values validated?

### 1.3 Fee Structure Changes
**From Napier 017-M, 019-M (FRAX):**
```solidity
// VULNERABLE: Assumes fixed fee
uint256 expectedReceived = amount * 99 / 100; // Assumes 1% fee

// SAFER: Query current fee
uint256 fee = externalProtocol.fee();
uint256 expectedReceived = amount * (10000 - fee) / 10000;
```

---

## 2. External Admin Actions

### 2.1 Admin Can Pause
**Description:** External protocol admin pauses, blocking our protocol
**From Napier 017-M (FRAX redemption pause):**
```solidity
// VULNERABLE: No handling for external pause
function withdraw(uint256 amount) {
    fraxEtherRedemptionQueue.enterRedemptionQueue(amount);
    // If FRAX pauses redemptions, this fails
    // And our users are stuck
}

// SAFER: Graceful degradation
function withdraw(uint256 amount) {
    try fraxEtherRedemptionQueue.enterRedemptionQueue(amount) {
        // Success path
    } catch {
        // Alternative path or informative revert
        revert ExternalProtocolPaused();
    }
}
```

### 2.2 Admin Can Upgrade
**Description:** External protocol upgrades maliciously
**Detection Pattern:**
- Is external contract upgradeable?
- What's the upgrade timelock?
- Is there a trusted admin assumption?

### 2.3 Admin Can Change Parameters
**Description:** External admin changes params affecting our protocol
**Examples:**
- Fee changes
- Collateral factor changes
- Interest rate model changes
- Whitelist/blacklist changes

---

## 3. Token Integration Risks

### 3.1 Non-Standard ERC-20 Behavior
**Detection Pattern:**
```solidity
// VULNERABLE: Assumes standard ERC-20
token.transfer(to, amount);
// USDT/BNB return void, not bool
// Fee-on-transfer tokens transfer less

// SAFER: Use SafeERC20
IERC20(token).safeTransfer(to, amount);

// For fee-on-transfer:
uint256 before = token.balanceOf(to);
token.safeTransferFrom(from, address(this), amount);
uint256 received = token.balanceOf(address(this)) - before;
```

### 3.2 Rebasing Token Integration
**Description:** Token balance changes without transfers
**Tokens:** stETH, AMPL, aTokens, etc.
**Detection Pattern:**
```solidity
// VULNERABLE: Caching rebasing token balance
uint256 balance = rebasingToken.balanceOf(address(this));
// ... time passes, rebase occurs ...
// balance is now stale

// SAFER: Always read fresh, or use shares
uint256 shares = stETH.sharesOf(address(this));
uint256 balance = stETH.getPooledEthByShares(shares);
```

### 3.3 Blacklistable Tokens
**Description:** USDC/USDT can blacklist addresses
**Detection Pattern:**
- What if user address is blacklisted?
- What if contract address is blacklisted?
- Are there alternative withdrawal paths?

### 3.4 Pausable Tokens
**Description:** Token transfers can be paused
**Detection Pattern:**
- What happens if token is paused?
- Are there time-sensitive operations that would fail?

### 3.5 Upgradeable Tokens
**Description:** Token implementation can change
**Detection Pattern:**
- Is token a proxy?
- Can token behavior change post-integration?
- Are there token upgrade monitoring alerts?

---

## 4. Cross-Protocol Composability

### 4.1 Flash Loan Attack Paths
**Description:** Flash loans enable complex multi-protocol attacks
**Detection Pattern:**
- Can attacker use flash loan to manipulate state?
- Are there cross-protocol invariants that can be broken?
- Is there flash loan protection (e.g., same-block check)?

### 4.2 Reentrancy Across Protocols
**Description:** Reentrancy via callback to different protocol
**Detection Pattern:**
```solidity
// Protocol A calls Protocol B
// Protocol B has callback to Protocol A
// State can be inconsistent

// Example: Curve read-only reentrancy
// Remove liquidity -> ETH callback -> Read Curve price (stale)
```

### 4.3 Shared Dependency Risk
**Description:** Multiple protocols depend on same vulnerable component
**Detection Pattern:**
- What's the shared oracle?
- What if shared dependency fails?
- Is there correlation between integrated protocols?

---

## 5. Bridge & Cross-Chain Risks

### 5.1 Message Verification
**Description:** Invalid cross-chain messages
**Detection Pattern:**
- How are cross-chain messages verified?
- Can messages be replayed?
- What's the source chain verification?

### 5.2 Token Mapping Issues
**Description:** Incorrect token mapping across chains
**Detection Pattern:**
- How are tokens mapped between chains?
- Can attacker create fake token on one chain?
- Are decimals consistent across chains?

### 5.3 Finality Assumptions
**Description:** Different chains have different finality
**Detection Pattern:**
- Is source chain finality sufficient?
- What happens on reorg?
- Are there minimum confirmation requirements?

---

## 6. Protocol-Specific Integration Patterns

### 6.1 Curve Integration
**Risks:**
- Read-only reentrancy via remove_liquidity
- Virtual price manipulation
- Pool imbalance risks
- Admin fee changes

**Detection Pattern:**
```solidity
// Check for Curve in integrated protocols
// Verify virtual price reads are reentrancy-safe
// Check admin key assumptions
```

### 6.2 Uniswap V3 Integration
**Risks:**
- Position NFT handling
- Tick crossing edge cases
- Fee collection timing
- Concentrated liquidity manipulation

### 6.3 Chainlink Integration
**Risks:**
- See oracle-manipulation.md for details
- Staleness, decimals, sequencer status

### 6.4 Compound/AAVE Integration
**Risks:**
- cToken/aToken exchange rate changes
- Borrow rate spikes
- Liquidation cascades
- Market supply caps

### 6.5 Lido/LST Integration
**Risks:**
- See staking-lsd.md for details
- Rebasing, slashing, withdrawal delays

---

## 7. Dependency Failure Modes

### 7.1 Graceful Degradation
**Description:** How protocol handles external failure
**Detection Pattern:**
- What happens if external call reverts?
- Is there a fallback mechanism?
- Can users recover funds if dependency fails?

### 7.2 Stuck Funds
**Description:** External failure causes funds to be stuck
**Examples:**
- Bridge goes down, can't withdraw
- Lending protocol pauses, can't redeem
- DEX illiquid, can't swap

**Detection Pattern:**
- Are there emergency withdrawal functions?
- Is there a guardian who can rescue funds?
- Are there time limits after which stuck funds can be recovered?

### 7.3 Cascading Failures
**Description:** One protocol failure triggers others
**Detection Pattern:**
- What's the dependency graph?
- Are there circular dependencies?
- Can failure of one cause failure of many?

---

## 8. Trust Assumptions

### 8.1 External Admin Trust
**Detection Questions:**
- Who are the external protocol admins?
- What can they do?
- Are timelocks in place?
- Is multisig required?

### 8.2 Oracle Provider Trust
**Detection Questions:**
- Who operates the oracle?
- Can they manipulate price?
- What's their track record?

### 8.3 Custodian Trust
**Detection Questions:**
- Are funds held by external custodian?
- What's their security?
- Are there insurance mechanisms?

---

## Audit Checklist

### Token Integration
- [ ] Standard ERC-20 compliance verified?
- [ ] Fee-on-transfer handling?
- [ ] Rebasing token handling?
- [ ] Blacklist/pause handling?

### External Protocol
- [ ] Behavior assumptions documented?
- [ ] Fee change handling?
- [ ] Pause/upgrade handling?
- [ ] Return value validation?

### Cross-Protocol
- [ ] Flash loan attack paths analyzed?
- [ ] Reentrancy across protocols checked?
- [ ] Shared dependency risks identified?

### Failure Modes
- [ ] Graceful degradation implemented?
- [ ] Stuck fund recovery possible?
- [ ] Cascading failures prevented?

### Trust Assumptions
- [ ] External admin risks documented?
- [ ] Oracle provider trust verified?
- [ ] Custodian risks assessed?

---

*Sources: Napier Finance findings, Rekt News, Trail of Bits reports*
*Last Updated: 2026-02-03*
