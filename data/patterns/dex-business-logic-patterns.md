# DEX Business Logic Vulnerability Patterns

**Source:** Salty.IO Code4rena Audit (2024-01)
**Analysis Date:** 2026-02-04
**Findings Analyzed:** 6 High, 31+ Medium

This document captures business logic vulnerabilities that automated tools typically miss, extracted from a comprehensive DEX audit.

---

## HIGH SEVERITY PATTERNS

### 1. External Contract Integration Risk - Missing Access Control

**Pattern ID:** DEX-H-001
**Category:** External Integration
**Likelihood:** Medium | **Impact:** High

**Description:**
External contracts (like OpenZeppelin's VestingWallet) may have permissionless functions that the integrating protocol assumes are restricted. When composing with external contracts, always verify access control assumptions.

**Vulnerable Pattern:**
```solidity
// VestingWallet.release() is PUBLIC and can be called by ANYONE
// Protocol assumed only Upkeep could call it
function step11() public onlySameContract {
    uint256 releaseableAmount = VestingWallet(payable(teamVestingWallet)).releasable(address(salt));
    VestingWallet(payable(teamVestingWallet)).release(address(salt));
    // PROBLEM: If someone called release() before this, releaseableAmount != actual released
    salt.safeTransfer(mainWallet, releaseableAmount);
}
```

**Detection Questions:**
- Does the protocol integrate with external contracts?
- Are there assumptions about who can call external contract functions?
- Does the external contract have permissionless functions that affect protocol state?

**Mitigation:**
- Query actual balances before/after external calls
- Don't assume external contract access patterns

---

### 2. First Depositor / First LP Attack

**Pattern ID:** DEX-H-002
**Category:** Initialization / Accounting
**Likelihood:** High | **Impact:** High

**Description:**
When a pool or staking system has no existing shares, the first depositor can manipulate ratios to steal rewards or break accounting. This applies to:
- Liquidity pools (first depositor inflation attack)
- Staking/reward systems (virtual rewards bypass)
- Vault share calculations

**Vulnerable Pattern:**
```solidity
function _increaseUserShare(address wallet, bytes32 poolID, uint256 increaseShareAmount) internal {
    uint256 existingTotalShares = totalShares[poolID];
    
    if (existingTotalShares != 0) {  // <-- SKIPPED for first depositor!
        uint256 virtualRewardsToAdd = Math.ceilDiv(totalRewards[poolID] * increaseShareAmount, existingTotalShares);
        user.virtualRewards += uint128(virtualRewardsToAdd);
    }
    // First depositor gets shares without virtual rewards
    user.userShare += uint128(increaseShareAmount);
}
```

**Detection Questions:**
- What happens when totalShares = 0?
- Can the first depositor claim rewards without offset?
- Can an attacker donate tokens to inflate ratios before others deposit?
- Are there uint128/uint256 overflow risks from ratio manipulation?

**Mitigation:**
- Lock initial shares (burn minimum amount)
- Initialize pools with small rewards
- Reset timers at protocol launch

---

### 3. Oracle Manipulation via Spot Price

**Pattern ID:** DEX-H-003
**Category:** Oracle / Price Feed
**Likelihood:** Medium | **Impact:** Critical

**Description:**
Using spot prices from pools as oracle feeds allows manipulation through:
- Flash loan attacks
- Large swaps that move prices
- MEV sandwich attacks

Even with arbitrage protection, small price movements are cheap to execute.

**Attack Cost Example:**
- 3% price move with 1000 ETH pools: ~0.0036 ETH
- 10% price move with 1000 ETH pools: ~0.0363 ETH

**Vulnerable Pattern:**
```solidity
// Using spot reserves as price feed
function getPriceBTC() external view returns (uint256) {
    (uint256 reservesWBTC, uint256 reservesUSDS) = pools.getPoolReserves(wbtc, usds);
    return (reservesUSDS * 10**8) / reservesWBTC;  // Manipulable!
}
```

**Detection Questions:**
- Does the protocol use spot prices from internal or external pools?
- What's the cost to move the price X%?
- Are liquidations or critical operations based on manipulable prices?
- Is TWAP used instead of spot?

**Mitigation:**
- Use TWAP with sufficient window (30+ minutes)
- Use multiple oracle sources with sanity checks
- Add price deviation limits between sources

---

### 4. Business Logic Bypass via State Manipulation

**Pattern ID:** DEX-H-004
**Category:** Business Logic
**Likelihood:** Medium | **Impact:** High

**Description:**
Users can manipulate protocol state to bypass critical functions like liquidation by:
- Resetting cooldown timers with minimal deposits
- Front-running critical operations
- Creating dependencies between unrelated functions

**Vulnerable Pattern:**
```solidity
// Liquidation checks cooldown
function liquidateUser(address wallet) external {
    _decreaseUserShare(wallet, collateralPoolID, userCollateralAmount, true);  // useCooldown = true
}

// Deposit resets cooldown
function _increaseUserShare(address wallet, bytes32 poolID, uint256 amount, bool useCooldown) internal {
    if (useCooldown) {
        require(block.timestamp >= user.cooldownExpiration, "Must wait for cooldown");
        user.cooldownExpiration = block.timestamp + modificationCooldown();  // RESET!
    }
}

// ATTACK: User deposits DUST amount before liquidation -> cooldown reset -> liquidation reverts
```

**Detection Questions:**
- Can users manipulate timestamps or cooldowns used in critical functions?
- Are there shared state variables between deposit/withdrawal and liquidation?
- Can minimal actions (DUST deposits) reset important timers?

**Mitigation:**
- Don't use cooldowns for liquidation
- Separate user-controlled vs protocol-controlled state
- Make critical functions atomic

---

### 5. Funds Sent to Wrong Destination

**Pattern ID:** DEX-H-005
**Category:** Accounting / Fund Flow
**Likelihood:** Low | **Impact:** Critical

**Description:**
Token transfers sent to incorrect addresses due to:
- Confusing similar contracts
- Wrong constant addresses
- Incomplete fund flow understanding

**Vulnerable Pattern:**
```solidity
function repayUSDS(uint256 amountRepaid) external {
    // USDS sent to USDS contract (to be burned)
    usds.safeTransferFrom(msg.sender, address(usds), amountRepaid);
    
    // But Liquidizer tracks what "should be burned"
    liquidizer.incrementBurnableUSDS(amountRepaid);
    
    // PROBLEM: USDS is at usds contract, but Liquidizer checks its OWN balance
    // Result: Protocol thinks more USDS needs burning than available
}
```

**Detection Questions:**
- Where do repaid/liquidated funds actually go?
- Does the contract tracking "burnable" amounts have the actual tokens?
- Are there mismatches between accounting and actual balances?

**Mitigation:**
- Verify token flows end at correct destinations
- Use balance checks rather than tracked amounts
- Test fund flow paths end-to-end

---

## MEDIUM SEVERITY PATTERNS

### 6. Rounding Direction Exploitation

**Pattern ID:** DEX-M-001
**Category:** Math / Rounding
**Likelihood:** High | **Impact:** Medium

**Description:**
When calculations round down (default Solidity behavior), small amounts can round to zero, allowing users to extract value without penalty.

**Vulnerable Pattern:**
```solidity
// Round down favors user, not protocol
uint256 virtualRewardsToRemove = (user.virtualRewards * decreaseShareAmount) / user.userShare;
// If decreaseShareAmount is small enough: virtualRewardsToRemove = 0
// User gets full rewards without virtual rewards deduction

claimableRewards = rewardsForAmount - virtualRewardsToRemove;  // Gets MORE than deserved
```

**Detection Questions:**
- Which direction does rounding favor?
- Can users make many small operations to accumulate rounding benefits?
- Are there minimum amounts that prevent dust exploitation?

**Mitigation:**
- Round against user for deductions (Math.ceilDiv)
- Enforce minimums to prevent dust attacks
- Consider protocol fee on small operations

---

### 7. Governance Vote Reuse via Transfer

**Pattern ID:** DEX-M-002
**Category:** Governance
**Likelihood:** Medium | **Impact:** Medium

**Description:**
If voting power is based on current token balance (not snapshot), users can:
- Vote with staked tokens
- Unstake and transfer to another address
- Vote again with same tokens

**Vulnerable Pattern:**
```solidity
function castVote(uint256 ballotID, Vote vote) external {
    uint256 userVotingPower = staking.userShareForPool(msg.sender, STAKED_SALT);
    // Uses CURRENT staked amount, not snapshot at proposal creation
    _votesCastForBallot[ballotID][vote] += userVotingPower;
}

function canFinalizeBallot(uint256 ballotID) external view returns (bool) {
    // Uses CURRENT total staked, not snapshot
    if (totalVotesCastForBallot(ballotID) < requiredQuorumForBallotType(ballot.ballotType))
        return false;
}
```

**Detection Questions:**
- Is voting power snapshotted at proposal creation?
- Can tokens be transferred between votes?
- What's the unstaking period vs voting period?

**Mitigation:**
- Snapshot voting power at proposal creation
- Use time-weighted voting power
- Require vote locking during voting period

---

### 8. Proposal/Ballot Name Collision

**Pattern ID:** DEX-M-003
**Category:** Governance / DoS
**Likelihood:** High | **Impact:** Medium

**Description:**
If proposals are identified by names that don't include all parameters, attackers can:
- Front-run legitimate proposals with same name
- Block proposal creation with poison proposals
- Create _confirm suffix exploits for multi-step proposals

**Vulnerable Pattern:**
```solidity
function proposeCallContract(address contractAddress, uint256 number, string description) {
    string ballotName = string.concat("callContract:", contractAddress);  // Missing: number, description
    require(openBallotsByName[ballotName] == 0, "Proposal exists");
    // ATTACK: Create proposal with wrong number, same name -> blocks correct proposal
}

// Multi-step confirmation exploit
require(openBallotsByName[string.concat(ballotName, "_confirm")] == 0);
// ATTACK: Create "setContract:priceFeed1_confirm" to block "setContract:priceFeed1"
```

**Detection Questions:**
- Do proposal names include ALL parameters?
- Can different parameters result in same name?
- Are there reserved suffixes (_confirm) that can be exploited?

**Mitigation:**
- Include hash of all parameters in ballot name
- Prevent user-controlled names with reserved patterns
- Use sender address in proposal ID

---

### 9. DUST Threshold Issues

**Pattern ID:** DEX-M-004
**Category:** Accounting / Edge Cases
**Likelihood:** Medium | **Impact:** Medium

**Description:**
DUST checks prevent pools from having too small reserves, but:
- Typos in checks (checking same variable twice)
- Single user scenarios can't be liquidated (would violate DUST)
- Manipulation via small amounts

**Vulnerable Pattern:**
```solidity
// TYPO: reserve0 checked twice, reserve1 never checked!
require((reserves.reserve0 >= PoolUtils.DUST) && (reserves.reserve0 >= PoolUtils.DUST));

// Single borrower can't be liquidated
function liquidateUser(address wallet) external {
    pools.removeLiquidity(...);  // Reverts if reserves would go below DUST
}
```

**Detection Questions:**
- Are both reserves checked in require statements?
- What happens when removing all liquidity would violate DUST?
- Can the last user in a pool be liquidated?

**Mitigation:**
- Test edge cases with single users
- Allow reserves to go to zero (not just above DUST)
- Review all dual-variable checks for typos

---

### 10. Unwhitelisting State Cleanup

**Pattern ID:** DEX-M-005
**Category:** State Management
**Likelihood:** Medium | **Impact:** Medium

**Description:**
When removing tokens/pools from whitelists, associated state (profits, rewards, shares) may not be cleared. Re-whitelisting can inherit stale state.

**Vulnerable Pattern:**
```solidity
function clearProfitsForPools() external {
    bytes32[] memory poolIDs = poolsConfig.whitelistedPools();  // Only current whitelist!
    for (uint256 i = 0; i < poolIDs.length; i++)
        _arbitrageProfits[poolIDs[i]] = 0;
}

// Unwhitelisted pool keeps _arbitrageProfits
// Re-whitelisting inherits old profits -> unfair reward distribution
```

**Detection Questions:**
- What state is associated with whitelisted items?
- Is state cleared when items are removed?
- What happens when items are re-added?

**Mitigation:**
- Clear all associated state on removal
- Use versioned identifiers for whitelisted items
- Track state lifecycle explicitly

---

### 11. Price Feed Volatility Blocking

**Pattern ID:** DEX-M-006
**Category:** Oracle / Availability
**Likelihood:** Medium | **Impact:** High

**Description:**
Multiple price feeds with deviation checks can ALL revert during volatility:
- TWAP lags behind spot during rapid moves
- Chainlink heartbeat delays
- Internal pool manipulation

**Vulnerable Pattern:**
```solidity
function _aggregatePrices(uint256 price1, uint256 price2, uint256 price3) internal view {
    // If closest two prices differ by > 3%, REVERT
    if (priceDiff > maximumPriceFeedPercentDifference)
        revert("Price difference too large");
}

// During 5% market move:
// - Chainlink: $38,800 (spot)
// - TWAP: $40,000 (lagging)
// - Internal: $38,000 (manipulated)
// Result: ALL combinations differ > 3%, everything reverts
```

**Detection Questions:**
- What happens when oracle sources diverge significantly?
- Is there a fallback when aggregation fails?
- Can an attacker cause divergence to block operations?

**Mitigation:**
- Use fallback to most trusted oracle instead of reverting
- Allow wider deviation during high volatility
- Implement circuit breakers instead of reverts

---

### 12. Suboptimal Arbitrage Calculation

**Pattern ID:** DEX-M-007
**Category:** MEV / Arbitrage
**Likelihood:** High | **Impact:** Medium

**Description:**
Bisection search for arbitrage amounts may:
- Miss profitable opportunities completely
- Find suboptimal amounts
- Enable sandwich attacks that capture protocol arbitrage

**Mathematical Issue:**
Optimal arbitrage can be calculated exactly:
```
bestArbAmountIn = (sqrt(A0*A1*B0*B1*C0*C1) - A0*B0*C0) / (A1*B1 + C0*(B0+A1))
```

But bisection search may test wrong ranges when pools are imbalanced.

**Detection Questions:**
- Is arbitrage calculation mathematically optimal?
- Can certain pool states cause zero arbitrage when profit exists?
- What's the maximum loss from suboptimal calculation?

**Mitigation:**
- Use closed-form solutions when available
- Ensure search ranges cover all profitable scenarios
- Test with extreme pool imbalances

---

## CHECKLIST FOR DEX AUDITS

### Initialization & First User
- [ ] What happens with zero total shares?
- [ ] Can first depositor manipulate ratios?
- [ ] Are rewards/virtual rewards properly initialized?

### Governance
- [ ] Are voting power snapshots used?
- [ ] Can votes be reused via transfers?
- [ ] Do proposal names include all parameters?
- [ ] Are there multi-step confirmation exploits?

### Price Feeds / Oracles
- [ ] Is spot vs TWAP used appropriately?
- [ ] Cost to move price X%?
- [ ] What happens when sources diverge?
- [ ] Chainlink heartbeat handling?

### State Management
- [ ] Is state cleared on removal/unwhitelisting?
- [ ] Re-adding items inherits stale state?
- [ ] Cooldowns shared between unrelated functions?

### Accounting
- [ ] Rounding direction for each calculation?
- [ ] DUST checks cover all variables?
- [ ] Fund destinations correct?
- [ ] Balance vs tracked amount consistency?

### Edge Cases
- [ ] Single user in pool/system?
- [ ] Zero values in calculations?
- [ ] Maximum/overflow values?
- [ ] Negative ticks in Uniswap calculations?

---

*Generated from Salty.IO audit analysis - 2026-02-04*
