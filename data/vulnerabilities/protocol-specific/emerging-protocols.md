# Emerging Protocol Vulnerabilities

This document covers security patterns and vulnerabilities in emerging DeFi protocol categories that are gaining significant adoption. These protocols introduce novel attack vectors that traditional auditing approaches may miss.

---

## 1. Restaking Protocols (EigenLayer, Symbiotic, Karak)

### 1.1 Overview

Restaking allows users to "reuse" staked ETH (or LSTs) to secure multiple services simultaneously, creating layered slashing risk and complex economic dependencies.

**Core Concepts:**
- **Operators:** Run validation software for AVSs (Actively Validated Services)
- **Stakers:** Delegate stake to operators
- **AVSs:** Services secured by restaked collateral
- **Slashing:** Penalty mechanism for operator misbehavior

### 1.2 Slashing Cascade Vulnerabilities

**Description:** A slashing event on one AVS can trigger cascading effects across all AVSs using the same operator.

```solidity
// VULNERABLE: No slashing isolation
contract NaiveRestaking {
    mapping(address => uint256) public stakedAmount;
    mapping(address => address[]) public operatorAVSs;
    
    function slash(address operator, uint256 amount) external onlyAVS {
        stakedAmount[operator] -= amount;
        // All other AVSs now have less collateral backing!
    }
}

// Attack Scenario:
// 1. Operator stakes 100 ETH
// 2. Registers with AVS_A (requires 50 ETH) and AVS_B (requires 50 ETH)
// 3. AVS_A slashes 60 ETH for misbehavior
// 4. AVS_B now has only 40 ETH backing - undercollateralized!

// SAFER: Slashing caps and isolation
contract SaferRestaking {
    struct Allocation {
        uint256 magnitude;  // Portion allocated to AVS
        uint256 slashable;  // Max that can be slashed
    }
    
    mapping(address => mapping(address => Allocation)) public allocations;
    uint256 public constant MAX_SLASHING_RATE = 50; // 50% max per AVS
    
    function slash(address operator, uint256 amount) external onlyAVS {
        Allocation storage alloc = allocations[operator][msg.sender];
        
        // Cap slashing to allocated amount
        uint256 maxSlash = alloc.slashable * MAX_SLASHING_RATE / 100;
        uint256 actualSlash = amount > maxSlash ? maxSlash : amount;
        
        alloc.slashable -= actualSlash;
        // Other AVSs maintain their collateral
    }
}
```

### 1.3 Operator Collusion Attacks

**Description:** Operators controlling significant restaked capital can collude to attack AVSs when the profit exceeds the slashing penalty.

```
Attack Economics:
- Total restaked: 1,000,000 ETH across system
- Operator controls: 100,000 ETH (10%)
- AVS secures: $500M bridge
- Slashing penalty: 50,000 ETH ($150M at $3000/ETH)
- Profit: $500M - $150M = $350M
```

**Mitigation Pattern:**

```solidity
contract AVSWithEconomicSecurity {
    uint256 public totalValueSecured;
    uint256 public requiredCollateral;
    uint256 public slashingPercentage;
    
    // Ensure economic security: collateral must exceed potential profit
    function updateSecurityParams() external {
        // Collateral should be > value secured * risk factor
        requiredCollateral = totalValueSecured * 2; // 200% collateralization
        
        // Dynamic slashing based on attack impact
        // Higher value = higher slashing percentage
    }
    
    // Maximum operator concentration
    uint256 public constant MAX_OPERATOR_SHARE = 33; // 33% max
    
    function registerOperator(address operator) external {
        uint256 operatorShare = operatorStake[operator] * 100 / totalStaked;
        require(operatorShare <= MAX_OPERATOR_SHARE, "Too concentrated");
    }
}
```

### 1.4 Withdrawal Timing Attacks

**Description:** Restaking introduces withdrawal delays. Operators may attempt to front-run slashing by withdrawing.

```solidity
// VULNERABLE: Immediate withdrawal
function withdraw(uint256 amount) external {
    require(stakedAmount[msg.sender] >= amount);
    stakedAmount[msg.sender] -= amount;
    token.transfer(msg.sender, amount);
    // Attacker can withdraw before slashing tx confirms
}

// SAFE: Queued withdrawals with slashing window
struct WithdrawalRequest {
    uint256 amount;
    uint256 requestTime;
    uint256 completableAfter;
}

uint256 public constant WITHDRAWAL_DELAY = 7 days;

mapping(address => WithdrawalRequest[]) public withdrawalQueue;
mapping(address => uint256) public frozenUntil; // Slashing investigation period

function queueWithdrawal(uint256 amount) external {
    require(frozenUntil[msg.sender] < block.timestamp, "Account frozen");
    
    withdrawalQueue[msg.sender].push(WithdrawalRequest({
        amount: amount,
        requestTime: block.timestamp,
        completableAfter: block.timestamp + WITHDRAWAL_DELAY
    }));
}

function completeWithdrawal(uint256 index) external {
    WithdrawalRequest storage req = withdrawalQueue[msg.sender][index];
    require(block.timestamp >= req.completableAfter, "Still in queue");
    require(frozenUntil[msg.sender] < req.requestTime, "Slashing pending");
    
    // Complete withdrawal...
}

function freezeForSlashing(address operator) external onlyAVS {
    frozenUntil[operator] = block.timestamp + SLASHING_WINDOW;
}
```

### 1.5 Delegation and Undelegation Race Conditions

```solidity
// VULNERABLE: Delegation changes take effect immediately
function delegate(address operator) external {
    delegations[msg.sender] = operator;
    operatorDelegated[operator] += stakedAmount[msg.sender];
}

// Attack:
// 1. Delegate to malicious operator
// 2. Operator commits slashable offense
// 3. Quickly undelegate before slashing is processed
// 4. Escape slashing while operator collects rewards

// SAFE: Delegation changes are queued
mapping(address => uint256) public delegationChangeCompletesAt;
uint256 public constant DELEGATION_DELAY = 3 days;

function queueDelegationChange(address newOperator) external {
    pendingDelegation[msg.sender] = newOperator;
    delegationChangeCompletesAt[msg.sender] = block.timestamp + DELEGATION_DELAY;
}

function completeDelegationChange() external {
    require(block.timestamp >= delegationChangeCompletesAt[msg.sender], "Still pending");
    // Process delegation change
}
```

### 1.6 AVS Registration Manipulation

```solidity
// VULNERABLE: AVS can be registered without proper validation
function registerAVS(address avsContract) external {
    registeredAVSs[avsContract] = true;
    // Malicious AVS can now slash operators!
}

// SAFE: AVS registration with governance and validation
struct AVSApplication {
    address avsContract;
    bytes32 codeHash;
    uint256 proposedAt;
    uint256 approvals;
}

function proposeAVS(address avsContract) external onlyGovernance {
    avsApplications[avsContract] = AVSApplication({
        avsContract: avsContract,
        codeHash: avsContract.codehash,
        proposedAt: block.timestamp,
        approvals: 0
    });
}

function approveAVS(address avsContract) external onlySecurityCouncil {
    AVSApplication storage app = avsApplications[avsContract];
    require(app.proposedAt > 0, "Not proposed");
    require(avsContract.codehash == app.codeHash, "Code changed");
    require(block.timestamp >= app.proposedAt + 7 days, "Timelock");
    
    app.approvals++;
    if (app.approvals >= REQUIRED_APPROVALS) {
        registeredAVSs[avsContract] = true;
    }
}
```

---

## 2. Intent-Based Protocols (CoW Protocol, UniswapX, 1inch Fusion)

### 2.1 Overview

Intent-based protocols allow users to express desired outcomes (intents) rather than specific execution paths. Solvers compete to fulfill intents, introducing new trust assumptions.

**Core Concepts:**
- **Intent:** User's desired outcome (e.g., "swap 1 ETH for maximum USDC")
- **Solver:** Third party that fulfills intents
- **Auction:** Mechanism to select best solver
- **Settlement:** On-chain execution of fulfilled intent

### 2.2 Intent Manipulation Attacks

**Description:** Vague or poorly specified intents can be fulfilled in ways that benefit solvers at users' expense.

```solidity
// VULNERABLE: Underspecified intent
struct Intent {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;  // Only constraint
}

// Attack: Solver fulfills at exactly minAmountOut even when better rate available
// User says "swap 1 ETH, minimum 3000 USDC"
// Market rate is 3500 USDC
// Solver fulfills at 3000 USDC, keeps 500 USDC

// SAFER: Oracle-referenced minimum
struct SaferIntent {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;
    address priceOracle;
    uint256 maxSlippageBps;  // e.g., 50 = 0.5%
    uint256 deadline;
}

function validateIntentFulfillment(
    SaferIntent calldata intent,
    uint256 actualAmountOut
) internal view {
    // Check minimum
    require(actualAmountOut >= intent.minAmountOut, "Below minimum");
    
    // Check oracle price (if provided)
    if (intent.priceOracle != address(0)) {
        uint256 oraclePrice = IOracle(intent.priceOracle).getPrice(
            intent.tokenIn, 
            intent.tokenOut
        );
        uint256 expectedOut = intent.amountIn * oraclePrice / 1e18;
        uint256 minAcceptable = expectedOut * (10000 - intent.maxSlippageBps) / 10000;
        require(actualAmountOut >= minAcceptable, "Worse than oracle");
    }
}
```

### 2.3 Solver Collusion and MEV Extraction

**Description:** Solvers can collude to extract MEV from users or manipulate auction outcomes.

```
Attack Scenario - Auction Manipulation:
1. Solver A and Solver B collude
2. User submits intent worth $100 profit to solver
3. Solver A bids $90 profit share to user
4. Solver B bids $50 (artificially low)
5. Solver A wins, keeps $10 extra vs competitive market

Defense Mechanisms:
```

```solidity
// Solver bonding and slashing
contract SolverRegistry {
    mapping(address => uint256) public solverBond;
    uint256 public constant MIN_BOND = 10 ether;
    
    mapping(address => uint256) public solverScore; // Reputation
    mapping(address => uint256) public fillCount;
    mapping(address => uint256) public userBenefitTotal;
    
    function registerSolver() external payable {
        require(msg.value >= MIN_BOND, "Insufficient bond");
        solverBond[msg.sender] = msg.value;
    }
    
    // Track solver quality
    function recordFill(
        address solver,
        uint256 userReceived,
        uint256 oracleValue
    ) internal {
        fillCount[solver]++;
        
        // Track how much better/worse than oracle
        if (userReceived >= oracleValue) {
            userBenefitTotal[solver] += userReceived - oracleValue;
            solverScore[solver] += 10; // Good fill
        } else {
            solverScore[solver] -= 1; // Below oracle (but above minimum)
        }
    }
    
    // Slash for provably bad behavior
    function slashSolver(address solver, bytes calldata proof) external {
        require(verifyMisbehavior(proof), "Invalid proof");
        uint256 slashAmount = solverBond[solver] / 2;
        solverBond[solver] -= slashAmount;
        // Distribute to affected users
    }
}
```

### 2.4 Intent Replay Attacks

```solidity
// VULNERABLE: No replay protection
struct Intent {
    address user;
    address tokenIn;
    uint256 amountIn;
    uint256 minAmountOut;
    bytes signature;
}

function fulfillIntent(Intent calldata intent) external {
    require(verifySignature(intent), "Invalid signature");
    // Execute swap...
    // Same intent can be replayed!
}

// SAFE: Nonce-based replay protection
struct SafeIntent {
    address user;
    address tokenIn;
    uint256 amountIn;
    uint256 minAmountOut;
    uint256 nonce;
    uint256 deadline;
    bytes signature;
}

mapping(address => uint256) public userNonces;
mapping(bytes32 => bool) public usedIntentHashes;

function fulfillIntent(SafeIntent calldata intent) external {
    require(block.timestamp <= intent.deadline, "Intent expired");
    
    bytes32 intentHash = keccak256(abi.encode(intent));
    require(!usedIntentHashes[intentHash], "Already fulfilled");
    require(intent.nonce == userNonces[intent.user], "Invalid nonce");
    
    usedIntentHashes[intentHash] = true;
    userNonces[intent.user]++;
    
    // Execute...
}
```

### 2.5 Partial Fill Exploitation

```solidity
// VULNERABLE: Partial fills without fair pricing
function fulfillPartial(Intent calldata intent, uint256 fillAmount) external {
    require(fillAmount <= intent.amountIn);
    
    uint256 amountOut = fillAmount * intent.minAmountOut / intent.amountIn;
    // Solver cherry-picks profitable portions
}

// Attack:
// Intent: Swap 100 ETH for min 300,000 USDC (3000 per ETH)
// Market: First 50 ETH can get 3100 USDC/ETH, next 50 only 2900
// Solver fills only the profitable 50 ETH portion
// User stuck with unfilled remainder at worse price

// SAFER: All-or-nothing or minimum fill requirements
struct Intent {
    // ...
    uint256 minFillPercentage; // e.g., 80% minimum fill
    bool allowPartialFill;
}

function fulfillPartial(Intent calldata intent, uint256 fillAmount) external {
    if (intent.allowPartialFill) {
        uint256 fillPercentage = fillAmount * 100 / intent.amountIn;
        require(fillPercentage >= intent.minFillPercentage, "Fill too small");
    } else {
        require(fillAmount == intent.amountIn, "Must fill completely");
    }
}
```

### 2.6 Cross-Intent MEV

```solidity
// Attack: Solver sees multiple intents and extracts cross-intent MEV
// Intent A: Buy 10 ETH with USDC (pushes price up)
// Intent B: Sell 5 ETH for USDC (benefits from higher price)
// 
// Solver executes B, then A, profiting from the ordering

// Defense: Batch auction with uniform clearing price
contract BatchAuction {
    struct Batch {
        Intent[] intents;
        uint256 clearingPrice;
        uint256 settlementBlock;
    }
    
    function settleBatch(
        Batch calldata batch,
        uint256 uniformPrice
    ) external onlySolver {
        // All intents in batch settle at same price
        // Eliminates ordering MEV
        require(block.number >= batch.settlementBlock, "Too early");
        
        for (uint i = 0; i < batch.intents.length; i++) {
            executeAtUniformPrice(batch.intents[i], uniformPrice);
        }
    }
}
```

---

## 3. Points and Airdrop Systems

### 3.1 Overview

Points systems have become the dominant mechanism for bootstrapping protocol usage, creating significant attack surface.

**Common Patterns:**
- Points earned for protocol usage (deposits, swaps, referrals)
- Future airdrop based on points
- Multipliers for early/loyal users

### 3.2 Sybil Farming Attacks

**Description:** Users create multiple wallets to multiply points/rewards.

```solidity
// VULNERABLE: No Sybil resistance
function earnPoints(address user, uint256 amount) internal {
    points[user] += amount * multiplier;
    // Anyone can create infinite wallets
}

// SAFER: Sybil resistance mechanisms
contract SybilResistantPoints {
    mapping(address => bool) public verifiedHuman;
    mapping(address => uint256) public onchainHistory;
    
    // Worldcoin/Gitcoin Passport verification
    function verifyHumanity(bytes calldata proof) external {
        require(IWorldID(worldId).verify(msg.sender, proof), "Not verified");
        verifiedHuman[msg.sender] = true;
    }
    
    // On-chain history requirements
    function calculateMultiplier(address user) public view returns (uint256) {
        uint256 base = 100; // 1x
        
        // Verified humans get bonus
        if (verifiedHuman[user]) {
            base += 50; // +0.5x
        }
        
        // Wallet age bonus
        if (onchainHistory[user] > 365 days) {
            base += 25; // +0.25x
        }
        
        // Transaction count bonus (harder to farm)
        uint256 txCount = historicalTxCount[user];
        if (txCount > 100) {
            base += 25;
        }
        
        return base;
    }
}
```

### 3.3 Points Manipulation via Flash Loans

```solidity
// VULNERABLE: Snapshot-based points
function snapshotPoints() external {
    for (uint i = 0; i < users.length; i++) {
        uint256 balance = token.balanceOf(users[i]);
        points[users[i]] += balance * POINTS_PER_TOKEN;
    }
}

// Attack:
// 1. Flash loan 1M tokens
// 2. Deposit into protocol just before snapshot
// 3. Earn points for 1M tokens
// 4. Withdraw and repay flash loan
// 5. Cost: flash loan fee (~0.05%)

// SAFER: Time-weighted average balance
contract TWABPoints {
    struct Observation {
        uint256 timestamp;
        uint256 balance;
        uint256 cumulativeBalance;
    }
    
    mapping(address => Observation[]) public observations;
    
    function updateObservation(address user, uint256 newBalance) internal {
        Observation storage last = observations[user][observations[user].length - 1];
        
        uint256 timeElapsed = block.timestamp - last.timestamp;
        uint256 cumulative = last.cumulativeBalance + last.balance * timeElapsed;
        
        observations[user].push(Observation({
            timestamp: block.timestamp,
            balance: newBalance,
            cumulativeBalance: cumulative
        }));
    }
    
    function getAverageBalance(
        address user,
        uint256 startTime,
        uint256 endTime
    ) public view returns (uint256) {
        // Calculate time-weighted average - immune to flash loans
        uint256 startCumulative = getCumulativeAt(user, startTime);
        uint256 endCumulative = getCumulativeAt(user, endTime);
        
        return (endCumulative - startCumulative) / (endTime - startTime);
    }
}
```

### 3.4 Referral System Exploitation

```solidity
// VULNERABLE: Circular referrals
mapping(address => address) public referrer;
uint256 public constant REFERRAL_BONUS = 10; // 10%

function setReferrer(address _referrer) external {
    require(referrer[msg.sender] == address(0), "Already set");
    referrer[msg.sender] = _referrer;
}

function earnPoints(uint256 amount) external {
    points[msg.sender] += amount;
    
    address ref = referrer[msg.sender];
    if (ref != address(0)) {
        points[ref] += amount * REFERRAL_BONUS / 100;
        // Attacker refers self through chain of wallets
    }
}

// Attack:
// Wallet A refers Wallet B
// Wallet B refers Wallet C
// ... (all controlled by attacker)
// Wallet Z refers Wallet A (circular!)

// SAFER: Referral depth limits and self-referral prevention
contract SafeReferrals {
    mapping(address => address) public referrer;
    mapping(address => uint256) public referralDepth;
    uint256 public constant MAX_DEPTH = 3;
    
    function setReferrer(address _referrer) external {
        require(referrer[msg.sender] == address(0), "Already set");
        require(_referrer != msg.sender, "Self-referral");
        require(referralDepth[_referrer] < MAX_DEPTH, "Too deep");
        
        // Check for circular referral
        address current = _referrer;
        for (uint i = 0; i < MAX_DEPTH; i++) {
            require(current != msg.sender, "Circular referral");
            current = referrer[current];
            if (current == address(0)) break;
        }
        
        referrer[msg.sender] = _referrer;
        referralDepth[msg.sender] = referralDepth[_referrer] + 1;
    }
}
```

### 3.5 Airdrop Claim Vulnerabilities

```solidity
// VULNERABLE: No deadline on claims
function claimAirdrop(uint256 amount, bytes32[] calldata proof) external {
    require(MerkleProof.verify(proof, merkleRoot, keccak256(abi.encodePacked(msg.sender, amount))));
    require(!claimed[msg.sender], "Already claimed");
    
    claimed[msg.sender] = true;
    token.transfer(msg.sender, amount);
}

// Issues:
// 1. Unclaimed tokens locked forever
// 2. No ability to recover/redistribute
// 3. Long claim windows enable price manipulation

// SAFER: Time-bounded claims with recovery
contract SafeAirdrop {
    uint256 public claimDeadline;
    uint256 public constant CLAIM_PERIOD = 90 days;
    
    function claimAirdrop(uint256 amount, bytes32[] calldata proof) external {
        require(block.timestamp <= claimDeadline, "Claim period ended");
        require(MerkleProof.verify(proof, merkleRoot, keccak256(abi.encodePacked(msg.sender, amount))));
        require(!claimed[msg.sender], "Already claimed");
        
        claimed[msg.sender] = true;
        token.transfer(msg.sender, amount);
    }
    
    // Governance can recover unclaimed tokens after deadline
    function recoverUnclaimed() external onlyGovernance {
        require(block.timestamp > claimDeadline, "Claim period active");
        uint256 remaining = token.balanceOf(address(this));
        token.transfer(treasury, remaining);
    }
}
```

### 3.6 Merkle Proof Vulnerabilities

```solidity
// VULNERABLE: Second preimage attack
function claimAirdrop(bytes32[] calldata proof, address account, uint256 amount) external {
    bytes32 leaf = keccak256(abi.encodePacked(account, amount));
    require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");
    // Attacker can potentially find collision
}

// SAFER: Double-hash leaves (prevents second preimage)
function claimAirdrop(bytes32[] calldata proof, address account, uint256 amount) external {
    // Double-hash to prevent length extension attacks
    bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
    require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");
    
    // Also verify caller is the account (prevent claim on behalf)
    require(msg.sender == account || delegates[account] == msg.sender, "Unauthorized");
}
```

### 3.7 Points-to-Token Conversion Gaming

```solidity
// VULNERABLE: Fixed conversion rate known in advance
uint256 public constant POINTS_PER_TOKEN = 1000;

function convertToTokens() external {
    uint256 tokens = points[msg.sender] / POINTS_PER_TOKEN;
    points[msg.sender] = 0;
    token.mint(msg.sender, tokens);
}

// Attack: Accumulate points knowing exact token value
// Market manipulates token price before conversion

// SAFER: Dynamic conversion based on total points
contract DynamicConversion {
    uint256 public totalTokensForAirdrop;
    uint256 public snapshotTotalPoints;
    bool public conversionRateLocked;
    
    function lockConversionRate() external onlyGovernance {
        snapshotTotalPoints = getTotalPoints();
        conversionRateLocked = true;
    }
    
    function convertToTokens() external {
        require(conversionRateLocked, "Conversion not started");
        
        // Pro-rata distribution
        uint256 userShare = points[msg.sender] * 1e18 / snapshotTotalPoints;
        uint256 tokens = totalTokensForAirdrop * userShare / 1e18;
        
        points[msg.sender] = 0;
        token.mint(msg.sender, tokens);
    }
}
```

---

## 4. Combined Attack Vectors

### 4.1 Restaking + Intent Exploitation

```
Attack: Operator runs solver for intent protocol
1. Operator sees valuable user intents
2. Operator front-runs/sandwiches intents using restaked capital
3. If caught and slashed, profit > slashing penalty
4. Economic security model broken
```

### 4.2 Points + Protocol Usage Gaming

```
Attack: Farm points via flash loan arbitrage
1. Flash loan large amount
2. Execute "usage" actions that earn points (deposits, swaps)
3. Unwind positions
4. Repeat across many blocks
5. Accumulate massive points with minimal capital at risk
```

---

## 5. Audit Checklist for Emerging Protocols

### Restaking Protocols
- [ ] Is slashing capped per AVS to prevent cascade?
- [ ] Are withdrawal delays sufficient to catch slashable offenses?
- [ ] Is there protection against front-running slashing?
- [ ] Are delegation changes properly queued?
- [ ] Is AVS registration gated with timelock/governance?
- [ ] Is operator concentration limited?
- [ ] Does economic security exceed value-at-risk?

### Intent-Based Protocols
- [ ] Are intents fully specified (oracle reference, slippage, deadline)?
- [ ] Is replay protection implemented (nonce, hash)?
- [ ] Are solver incentives aligned with users?
- [ ] Is there solver bond/slashing for misbehavior?
- [ ] Are partial fills handled fairly?
- [ ] Is cross-intent MEV mitigated (batch auctions)?
- [ ] Can users cancel pending intents?

### Points/Airdrop Systems
- [ ] Is Sybil resistance implemented?
- [ ] Is time-weighted average used instead of snapshots?
- [ ] Are referral chains limited in depth?
- [ ] Is self-referral prevented?
- [ ] Are claims time-bounded with recovery?
- [ ] Are merkle proofs double-hashed?
- [ ] Is conversion rate determined fairly (not manipulable)?
- [ ] Can points be transferred? (creates market for farming)

---

## 6. Real-World Case Studies

### EigenLayer M1 (2024)
- **Issue:** Unbounded operator registration allowed potential DoS
- **Impact:** Could prevent legitimate operators from registering
- **Fix:** Rate limiting and bonding requirements

### CoW Protocol Solver Incident (2023)
- **Issue:** Solver submitted suboptimal execution
- **Impact:** ~$166K user value extraction
- **Fix:** Solver slashing and improved monitoring

### Blur Points Season 2 (2023)
- **Issue:** Wash trading to farm points
- **Impact:** Billions in fake volume
- **Lesson:** Activity-based points vulnerable to manipulation

### LayerZero Sybil Detection (2024)
- **Issue:** Mass sybil farming before airdrop snapshot
- **Impact:** 803,000 addresses filtered
- **Lesson:** On-chain clustering analysis post-hoc

---

*Document created: 2026-02-05 04:00 AM*
*Last updated: 2026-02-05 04:00 AM*
*Estimated size: ~22KB*
