# Staking & Liquid Staking Derivative (LSD) Vulnerability Patterns

Protocol types: Lido, Rocket Pool, Frax, restaking protocols (EigenLayer)

## 1. Exchange Rate Manipulation

### 1.1 Share Inflation Attack
**Description:** First depositor inflates share value
**Attack Vector:**
1. Deposit 1 wei to become first staker
2. Donate large amount directly to contract
3. Share price now massively inflated
4. Next depositors lose funds to rounding

**Detection Pattern:**
```solidity
// VULNERABLE: No minimum shares
function deposit(uint256 amount) {
    shares = amount * totalShares / totalAssets();
}

// SAFER: Burn minimum shares on first deposit
if (totalShares == 0) {
    shares = amount - MINIMUM_SHARES;
    _mint(address(0), MINIMUM_SHARES);
}
```

### 1.2 Exchange Rate Decrease Race
**From Napier 012-H:**
```solidity
// VULNERABLE: Redemption during rate decrease
// When exchange rate decreases (slashing, etc.)
// First redeemer gets more underlying per share
// Last redeemer gets less

// Race condition: Everyone rushes to redeem first
```

**Detection Pattern:**
- What happens when exchange rate decreases?
- Is there queue/delay on withdrawals?
- Are there mechanisms to prevent bank runs?

### 1.3 Rebasing vs Non-Rebasing
**Description:** Confusion between rebasing and non-rebasing LSDs
**Detection Pattern:**
```solidity
// VULNERABLE: Treating stETH like wstETH
uint256 balance = stETH.balanceOf(address(this));
// Later...
require(stETH.balanceOf(address(this)) == balance);
// FAILS: stETH balance changed due to rebase

// SAFER: Use wrapped version or track shares
uint256 shares = stETH.sharesOf(address(this));
```

---

## 2. Withdrawal Queue Vulnerabilities

### 2.1 Queue Manipulation
**Description:** Front-run withdrawal queue position
**Attack Vector:**
1. Monitor large withdrawal requests
2. Front-run to get earlier queue position
3. If protocol pays interest during queue, get more

### 2.2 Buffer Manipulation DoS
**From Napier 014-H:**
```solidity
// VULNERABLE: Withdrawal relies on buffer
// Attacker calculates exact deposit to drain buffer
// Then requests withdrawal that requires buffer
// Withdrawal DoS'd until buffer replenished

// Example: Lido stETH buffer mechanics
```

**Detection Pattern:**
- What is buffer/instant-withdrawal pool?
- Can attacker drain buffer?
- What happens when buffer is empty?

### 2.3 Withdrawal Delay Exploitation
**Description:** Exploit long withdrawal delays
**Attack Vector:**
1. User requests withdrawal
2. During delay period, slashing event occurs
3. User's withdrawal request may get stale price
4. Or may receive slashed amount

**Detection Pattern:**
- How long is withdrawal delay?
- Is withdrawal amount locked at request or completion?
- What happens to pending withdrawals during slashing?

---

## 3. Slashing & Penalty Handling

### 3.1 Slashing Distribution Unfairness
**Description:** How slashing losses are distributed
**Detection Pattern:**
- Is slashing socialized or per-validator?
- Can large staker exit before slashing is processed?
- Are pending withdrawals affected by slashing?

### 3.2 Reporting Delay Exploitation
**Description:** Exploit delay in slashing reports
**Attack Vector:**
1. Validator gets slashed on beacon chain
2. Protocol takes time to update
3. During delay, stakers can exit at old exchange rate
4. Remaining stakers absorb more loss

### 3.3 Over-Slashing Issues
**Description:** Accounting issues when slashing exceeds stake
**Detection Pattern:**
- What happens if slashing > validator stake?
- Can this create bad debt?
- How is negative balance handled?

---

## 4. Operator/Validator Risks

### 4.1 Malicious Operator
**Description:** Node operator acts maliciously
**Attack Vectors:**
- Voluntary exit before slashing
- MEV extraction beyond protocol rules
- Key compromise and theft

**Detection Pattern:**
- How are operators selected/rotated?
- What's the economic security (operator stake)?
- Can operator steal funds directly?

### 4.2 Operator Coordination Attack
**Description:** Multiple operators collude
**Detection Pattern:**
- What % of operators needed to attack?
- Are there rate limits on operator actions?
- How is operator set diversity ensured?

### 4.3 MEV Distribution Issues
**Description:** Unfair MEV distribution between stakers/operators
**Detection Pattern:**
- How is MEV captured and distributed?
- Can operators extract MEV secretly?
- Are there mechanisms to verify MEV distribution?

---

## 5. Oracle & Reporting Vulnerabilities

### 5.1 Beacon Chain Oracle Manipulation
**Description:** Manipulation of beacon chain state reports
**Detection Pattern:**
- Who reports beacon chain state?
- How many reporters needed?
- Can stale/incorrect reports be exploited?

### 5.2 Total Assets Manipulation
**Description:** Inflate/deflate totalAssets for profit
**From Napier 020-H (stETH conversion):**
```solidity
// VULNERABLE: Incorrect total assets calculation
function totalAssets() returns (uint256) {
    return stETH.balanceOf(address(this)); 
    // Wrong: should convert stETH to ETH
}

// SAFER: Proper conversion
function totalAssets() returns (uint256) {
    return stETH.getPooledEthByShares(stETH.sharesOf(address(this)));
}
```

### 5.3 Yield Calculation Errors
**Description:** Incorrect yield/APY calculation
**Detection Pattern:**
- How is yield calculated (spot vs rolling)?
- Can attacker manipulate yield display?
- Are there flash loan concerns for yield?

---

## 6. Restaking Specific Risks (EigenLayer, etc.)

### 6.1 Layered Slashing Risk
**Description:** Multiple slashing conditions stack
**Attack Vector:**
1. User restakes LST on EigenLayer
2. Original staking protocol gets slashed
3. EigenLayer AVS also gets slashed
4. User gets double-slashed

### 6.2 Withdrawal Path Confusion
**Description:** Complex withdrawal paths across protocols
**Detection Pattern:**
- What's the withdrawal path through all layers?
- Can one layer block another's withdrawal?
- Are there priority issues between layers?

### 6.3 Operator Set Overlap
**Description:** Same operators across multiple AVS
**Detection Pattern:**
- If operator fails one AVS, what happens to others?
- Is there correlation risk tracking?

---

## 7. Integration Vulnerabilities

### 7.1 Wrapper Token Accounting
**Description:** Wrapped LST accounting issues
**Detection Pattern:**
```solidity
// VULNERABLE: Assuming 1:1 wrapper ratio
uint256 underlying = wstETH.balanceOf(address(this));

// SAFER: Use proper conversion
uint256 underlying = wstETH.getStETHByWstETH(
    wstETH.balanceOf(address(this))
);
```

### 7.2 DeFi Integration Risks
**Description:** Using LSTs in DeFi creates new risks
**Examples:**
- LST as collateral in lending: liquidation cascade
- LST in AMM: impermanent loss + slashing risk
- LST in yield vault: withdrawal timing issues

### 7.3 Depeg Risk
**Description:** LST trading below underlying value
**Detection Pattern:**
- What happens to integrations during depeg?
- Are liquidations triggered by market price or exchange rate?
- Can depeg be exploited for arbitrage?

---

## 8. Protocol-Specific Patterns

### 8.1 Lido-Specific
**Detection Questions:**
- [ ] stETH vs wstETH handling correct?
- [ ] Share conversion used instead of balance?
- [ ] Buffer mechanics understood?
- [ ] Rebasing properly handled?

### 8.2 Rocket Pool-Specific
**Detection Questions:**
- [ ] rETH exchange rate manipulation resistance?
- [ ] Minipool lifecycle handled?
- [ ] Node operator deposit amounts?
- [ ] RPL token staking implications?

### 8.3 Frax-Specific (from Napier findings)
**Detection Questions:**
- [ ] sfrxETH vs frxETH conversion correct?
- [ ] Admin fee changes handled?
- [ ] Redemption queue timing?
- [ ] Validator key management?

---

## 9. Edge Cases

### 9.1 Zero Amount Operations
**From Napier 008-M:**
```solidity
// VULNERABLE: Zero amount causes revert in external call
function stake(uint256 amount) {
    lidoContract.submit(amount); // Reverts on 0
}

// SAFER: Check amount first
require(amount > 0, "Amount must be positive");
```

### 9.2 First/Last Staker Edge Cases
**Detection Pattern:**
- What happens with first stake?
- What happens when last staker exits?
- Can total staked reach zero after having stakers?

### 9.3 Minimum Stake Requirements
**Detection Pattern:**
- Are minimum stake requirements enforced?
- What happens to dust amounts?
- Can attacker create many small positions?

---

## Audit Checklist

### Exchange Rate
- [ ] First depositor protection?
- [ ] Exchange rate decrease handling?
- [ ] Rebasing token handling correct?

### Withdrawals
- [ ] Withdrawal delay appropriate?
- [ ] Queue manipulation prevented?
- [ ] Buffer DoS prevented?

### Slashing
- [ ] Slashing socialization fair?
- [ ] Reporting delay handled?
- [ ] Bad debt scenario handled?

### Operators
- [ ] Operator stake requirements?
- [ ] Operator rotation possible?
- [ ] MEV distribution fair?

### Integrations
- [ ] Wrapper conversion correct?
- [ ] DeFi integration risks considered?
- [ ] Depeg scenario handled?

---

*Sources: Lido audits, Rocket Pool security reviews, EigenLayer docs, Napier findings*
*Last Updated: 2026-02-03*
