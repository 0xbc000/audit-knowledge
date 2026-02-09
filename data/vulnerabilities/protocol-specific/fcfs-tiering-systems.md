# FCFS & Tiered Reward System Vulnerabilities

First-Come-First-Served (FCFS) and tiered staking systems introduce unique attack vectors related to position management, tier boundary calculations, and ranking data structures.

---

## 1. Tier Boundary Calculation Vulnerabilities

### 1.1 Integer Division Edge Cases

**Description:** Tier boundary calculations using integer division can fail at specific staker count modulo values.

**Common Bug Pattern:**
```solidity
// VULNERABLE: Edge case at stakerCount % 10 == 4
function getTierCounts(uint256 totalStakers) internal pure returns (uint256 t1, uint256 t2) {
    t1 = totalStakers * 20 / 100;  // 20% in Tier 1
    t2 = totalStakers * 30 / 100;  // 30% in Tier 2
    // t3 = remainder
}

// At 104 stakers:
// t1 = 104 * 20 / 100 = 20.8 → 20 (floor)
// t2 = 104 * 30 / 100 = 31.2 → 31
// At 105 stakers:
// t1 = 105 * 20 / 100 = 21
// t2 = 105 * 30 / 100 = 31.5 → 31 (same as before!)
// PROBLEM: t2 count same but boundary position changes!
```

**Real Case (LayerEdge - May 2025):**
- Tier boundary at 10N+4 staker count failed to update correctly
- Code used `old_boundary` instead of `new_boundary` for promotion
- Users stuck in wrong tier, receiving lower APY

**Fix Pattern:**
```solidity
// SAFE: Use correct boundary for promotion/demotion
function updateTiers(bool isRemoval) internal {
    (uint256 old_t1, uint256 old_t2) = getTierCounts(oldStakerCount);
    (uint256 new_t1, uint256 new_t2) = getTierCounts(newStakerCount);
    
    // For tier 2 boundary updates
    uint256 old_boundary = old_t1 + old_t2;
    uint256 new_boundary = new_t1 + new_t2;
    
    if (new_boundary > old_boundary) {
        // Promotion: update users from old_boundary+1 to new_boundary
        for (uint256 rank = old_boundary + 1; rank <= new_boundary; rank++) {
            _updateUserTier(rank, Tier.Tier2);
        }
    } else if (new_boundary < old_boundary) {
        // Demotion: update users from new_boundary+1 to old_boundary
        for (uint256 rank = new_boundary + 1; rank <= old_boundary; rank++) {
            _updateUserTier(rank, Tier.Tier3);
        }
    } else {
        // CRITICAL: Even when counts are same, boundary position may change!
        // Use NEW boundary for add, OLD boundary for remove
        if (!isRemoval) {
            _updateUserTier(new_boundary, Tier.Tier2);  // ✅ Correct
        } else {
            _updateUserTier(old_boundary, Tier.Tier3);
        }
    }
}
```

**Audit Checklist:**
- [ ] Test tier calculations at modulo edge cases (10N, 10N+4, 10N+5, etc.)
- [ ] Verify boundary updates use correct NEW vs OLD boundary
- [ ] Check integer division rounding direction (floor vs ceil)

---

### 1.2 Cascading Update Gas DoS

**Description:** When tier boundaries shift, updating all affected users can consume excessive gas.

**Attack Pattern:**
```solidity
// VULNERABLE: O(k × log n) complexity per stake/unstake
function _checkBoundaries() internal {
    // If 10 users need tier updates...
    for (uint256 rank = old_boundary + 1; rank <= new_boundary; rank++) {
        _findAndRecordTierChange(rank);  // O(log n) tree query each
    }
}

// Gas Impact by Scale:
// 10 users:    ~650k-1.5M gas per tx (manageable)
// 100 users:   ~1-3M gas per tx (expensive)  
// 1000+ users: ~5-15M gas per tx (DoS risk)
// 10000 users: May exceed block gas limit
```

**Mitigation Patterns:**

```solidity
// PATTERN 1: Bounded Iteration
uint256 constant MAX_TIER_UPDATES_PER_TX = 50;

function _checkBoundaries() internal {
    uint256 updates = 0;
    for (uint256 rank = pendingUpdateStart; rank <= boundary && updates < MAX_TIER_UPDATES_PER_TX; rank++) {
        _updateUserTier(rank);
        updates++;
    }
    if (rank <= boundary) {
        pendingUpdateStart = rank;  // Continue in next tx
        emit PartialTierUpdate(rank, boundary);
    }
}

// PATTERN 2: Lazy Evaluation
mapping(address => uint256) public lastTierUpdateTime;

function getCurrentTier(address user) public view returns (Tier) {
    uint256 rank = getUserRank(user);
    // Calculate tier dynamically based on current state
    return _computeTierFromRank(rank, stakerCountInTree);
}

// Only update stored tier when needed (claim, unstake, etc.)
function _syncUserTier(address user) internal {
    Tier currentTier = getCurrentTier(user);
    if (users[user].storedTier != currentTier) {
        _recordTierChange(user, currentTier);
    }
}
```

**Audit Checklist:**
- [ ] Calculate worst-case gas for tier updates at scale (1k, 10k, 100k users)
- [ ] Verify tier update loops are bounded
- [ ] Check if lazy evaluation can be used instead of eager updates

---

## 2. Ranking Data Structure Vulnerabilities

### 2.1 Fenwick Tree / Segment Tree Issues

**Description:** Fenwick trees (Binary Indexed Trees) used for O(log n) rank queries can have consistency issues.

**Common Issues:**

```solidity
// ISSUE 1: Stale Tree State
// Tree not updated when underlying stake changes
function transfer(address to, uint256 amount) external {
    users[msg.sender].balance -= amount;
    users[to].balance += amount;
    // BUG: Fenwick tree not updated!
    // Ranks now incorrect
}

// ISSUE 2: Off-by-one in Rank Calculation
function getRank(address user) public view returns (uint256) {
    // Fenwick tree returns cumulative frequency
    return stakerTree.query(users[user].joinId);  // May be 0-indexed or 1-indexed
}

// ISSUE 3: Tree Size Limit
stakerTree.size = MAX_USERS;  // e.g., 100_000_000
// What happens when exceeded? Overflow? Revert?
```

**Fix Pattern:**
```solidity
// SAFE: Maintain tree consistency
function _updateStake(address user, uint256 newBalance) internal {
    uint256 oldBalance = users[user].balance;
    users[user].balance = newBalance;
    
    // Update tree whenever stake changes
    if (oldBalance == 0 && newBalance > 0) {
        _addToTree(user);
    } else if (oldBalance > 0 && newBalance == 0) {
        _removeFromTree(user);
    }
    // Note: If ranking by stake amount (not join time), 
    // tree needs rebalancing on every stake change
}
```

---

### 2.2 Ghost Staker Attacks

**Description:** Zero-balance or below-minimum stakers remaining in ranking structures steal tier slots from active stakers.

**Attack Pattern (LayerEdge - May 2025):**
```solidity
// VULNERABLE: Removal condition fails at minStakeAmount = 0
function _unstake(uint256 amount) internal {
    users[msg.sender].balance -= amount;
    
    // BUG: 0 < 0 = false, so user stays in tree with 0 balance!
    if (!user.outOfTree && user.balance < minStakeAmount) {
        _removeFromTree(msg.sender);
    }
}

// Attack:
// 1. Admin sets minStakeAmount = 0
// 2. Attacker stakes 1 wei → joins tree at rank 1 (Tier 1)
// 3. Attacker unstakes 1 wei → balance = 0, but stays in tree
// 4. Attacker occupies Tier 1 slot with 0 stake
// 5. Real stakers pushed to lower tiers
```

**Fix Pattern:**
```solidity
// SAFE: Explicit zero-balance check
function _unstake(uint256 amount) internal {
    users[msg.sender].balance -= amount;
    
    // Always remove if balance is 0 OR below minimum
    if (!user.outOfTree && (user.balance == 0 || user.balance < minStakeAmount)) {
        _removeFromTree(msg.sender);
    }
}

// Also validate minStakeAmount is reasonable
function setMinStakeAmount(uint256 amount) external onlyAdmin {
    require(amount >= MIN_REASONABLE_STAKE, "Min stake too low");
    minStakeAmount = amount;
}
```

**Audit Checklist:**
- [ ] Test with minStakeAmount = 0 edge case
- [ ] Verify zero-balance stakers are removed from ranking
- [ ] Check `<` vs `<=` comparisons in removal logic
- [ ] Validate tree size matches actual active staker count

---

## 3. FCFS Position Gaming

### 3.1 Front-Running Position Claims

**Description:** In FCFS systems, transaction ordering determines tier assignment.

```solidity
// VULNERABLE: Pure FCFS allows front-running
function stake(uint256 amount) external {
    require(amount >= minStakeAmount);
    joinId = nextJoinId++;  // Lower joinId = higher tier
    _addToTree(msg.sender);
}

// Attack:
// 1. Attacker monitors mempool for large stakers
// 2. Front-runs with own stake to claim earlier position
// 3. Victim gets lower tier despite staking more
```

**Mitigation Patterns:**
```solidity
// PATTERN 1: Commit-Reveal
mapping(bytes32 => uint256) public stakeCommitments;
uint256 constant COMMIT_DELAY = 1 hours;

function commitStake(bytes32 commitment) external {
    stakeCommitments[commitment] = block.timestamp;
}

function revealStake(uint256 amount, bytes32 salt) external {
    bytes32 commitment = keccak256(abi.encodePacked(msg.sender, amount, salt));
    require(stakeCommitments[commitment] > 0, "Not committed");
    require(block.timestamp >= stakeCommitments[commitment] + COMMIT_DELAY, "Too early");
    _executeStake(msg.sender, amount);
}

// PATTERN 2: Stake Amount Weighting
// Instead of pure FCFS, weight by stake amount × time
function getEffectivePosition(address user) public view returns (uint256) {
    return users[user].stakedAmount * (block.timestamp - users[user].stakeTime);
}
```

---

### 3.2 Tier Manipulation via Stake/Unstake Timing

**Description:** Repeatedly staking/unstaking to game tier assignments during boundary shifts.

```solidity
// Attack Pattern:
// 1. Monitor when boundary is about to shift (e.g., 99 → 100 stakers)
// 2. Stake just before boundary shift to get Tier 1
// 3. Unstake and restake to maintain position
```

**Mitigation:**
```solidity
// Cooldown between stake/unstake
mapping(address => uint256) public lastActionTime;
uint256 constant ACTION_COOLDOWN = 24 hours;

function stake(uint256 amount) external {
    require(block.timestamp >= lastActionTime[msg.sender] + ACTION_COOLDOWN);
    // ...
    lastActionTime[msg.sender] = block.timestamp;
}

function unstake(uint256 amount) external {
    require(block.timestamp >= lastActionTime[msg.sender] + ACTION_COOLDOWN);
    // ...
    lastActionTime[msg.sender] = block.timestamp;
}
```

---

## 4. Audit Checklist: FCFS & Tiering Systems

### Tier Boundary Logic
- [ ] Test all modulo edge cases (10N, 10N+1, ..., 10N+9)
- [ ] Verify NEW vs OLD boundary used correctly for promotions/demotions
- [ ] Check integer division direction (floor/ceil/round)
- [ ] Validate tier percentage calculations sum to 100%

### Ranking Data Structures
- [ ] Zero-balance stakers properly removed from ranking
- [ ] Tree operations maintain consistency with stake state
- [ ] Tree size limits handled gracefully
- [ ] Rank queries return correct 0-indexed or 1-indexed values

### Gas & DoS
- [ ] Calculate worst-case gas for tier updates at 1k/10k/100k users
- [ ] Tier update loops bounded or use lazy evaluation
- [ ] Mass stake/unstake scenarios don't cause DoS

### Position Gaming
- [ ] Front-running mitigation for position claims
- [ ] Cooldowns prevent stake/unstake gaming
- [ ] Consider stake amount weighting vs pure FCFS

### Admin Controls
- [ ] minStakeAmount cannot be set to 0 (or zero is handled)
- [ ] APY rates bounded to reasonable ranges
- [ ] Reward withdrawal doesn't impact active stakers

---

## Real-World Case Studies

### LayerEdge (Sherlock - May 2025)
- **Protocol:** Bitcoin-backed L2 staking with FCFS tiers
- **Findings:** 8 High severity
- **Key Issues:**
  1. Gas DoS at scale (O(k × log n) tier updates)
  2. Tier boundary bug at 10N+4 staker count
  3. Ghost stakers with minStakeAmount=0
  4. Wrong boundary index in tier updates

**Lessons:**
- FCFS/tiering systems require extensive edge case testing
- Integer division in tier calculations is error-prone
- Ranking data structures must stay consistent with stake state

---

*Created: 2026-02-07 04:00 AM (Asia/Taipei)*
*Source: LayerEdge Sherlock Contest Analysis*
