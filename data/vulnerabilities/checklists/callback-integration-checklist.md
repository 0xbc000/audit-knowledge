# Callback & External Integration Audit Checklist

> **Purpose:** Systematic review of callback-related and external integration vulnerabilities
> **Priority:** HIGH - These patterns caused multiple H/M findings in Revert Lend benchmark

---

## 1. ERC721/ERC1155 Callback Security

### Transfer Method Audit
- [ ] **Identify all `safeTransferFrom` calls**
  - Document: `file:line` - `from` - `to` - `context`
  - For each: Can `to` be a malicious contract?
  
- [ ] **State ordering analysis (CEI check)**
  - For each safeTransferFrom:
    - [ ] What state is READ before the transfer?
    - [ ] What state is WRITTEN before the transfer?
    - [ ] What state is accessible in callback?
    - [ ] Can callback modify that state?

### DoS Vectors
- [ ] **Liquidation callback DoS**
  - [ ] Does liquidation use `safeTransferFrom`?
  - [ ] Can liquidated user be a contract?
  - [ ] What if `onERC721Received` reverts?
  - [ ] Is there fallback for failed transfer?

- [ ] **Automation/Keeper DoS**
  - [ ] What automated functions use safeTransferFrom?
  - [ ] Can recipients block automation?
  - [ ] What's the impact of blocked automation?

### Reentrancy in Callbacks
- [ ] **All callback-sensitive functions**
  - [ ] Is `nonReentrant` applied?
  - [ ] If not, is state finalized before callback?
  - [ ] Can related functions be called during callback?

### Remediation Patterns
- [ ] Pull pattern available for stuck transfers?
- [ ] Gas limits on external calls?
- [ ] Try-catch with fallback?

---

## 2. External Protocol Integration

### Integration Inventory
- [ ] **List all external protocol calls**
  - Protocol name - Contract - Function - Purpose
  - Trust level: Immutable / Upgradeable / Admin-controlled

### Assumption Validation
- [ ] **For each integration:**
  - [ ] What assumptions about external behavior?
  - [ ] Are assumptions documented?
  - [ ] What if external contract is upgraded?
  - [ ] What if external contract is paused?

### External Admin Risks
- [ ] **Can external admin actions break this protocol?**
  - [ ] Token blacklisting
  - [ ] Contract upgrades
  - [ ] Parameter changes
  - [ ] Pause/unpause

### Failure Handling
- [ ] **What if external call fails?**
  - [ ] Reverts - is there fallback?
  - [ ] Returns bad data - is it validated?
  - [ ] External contract paused - what happens?

---

## 3. Oracle Integration

### Oracle Security
- [ ] **Oracle source identification**
  - [ ] Chainlink? Uniswap TWAP? Custom?
  - [ ] What's the trust model?
  
- [ ] **Manipulation resistance**
  - [ ] TWAP period (< 30 min is risky)
  - [ ] Liquidity depth validation?
  - [ ] Multi-oracle validation?
  - [ ] Circuit breakers for large moves?

### Uniswap V3 TWAP Specific
- [ ] **Tick math correctness**
  - [ ] Negative tick rounding handled?
  - [ ] Compare with canonical OracleLibrary
  
- [ ] **Observation cardinality**
  - [ ] Cardinality checked before TWAP?
  - [ ] History age validated?

### Oracle Failure Modes
- [ ] **What if oracle returns 0?**
- [ ] **What if oracle reverts?**
- [ ] **What if oracle returns stale data?**
- [ ] **Sequencer downtime (L2)?**

---

## 4. Token Integration

### Token Type Compatibility
- [ ] **Fee-on-transfer tokens**
  - [ ] Balance checked before/after transfer?
  - [ ] Or explicitly blocked?
  
- [ ] **Rebasing tokens**
  - [ ] Internal accounting matches external balance?
  - [ ] Or explicitly blocked?

- [ ] **Tokens without return values**
  - [ ] Using SafeERC20?
  - [ ] Or using low-level call with success check?

- [ ] **Zero transfer behavior**
  - [ ] Tokens that revert on zero handled?
  - [ ] Zero amount checks before transfer?

### Permit Integration
- [ ] **Permit token validation**
  - [ ] Permit token address hardcoded (not user-provided)?
  - [ ] Permit failures not silently swallowed?
  
- [ ] **Signature validation**
  - [ ] Deadline checked?
  - [ ] Nonce handled correctly?

---

## 5. State Transition Safety

### Feature Toggle Analysis
- [ ] **List all toggleable features**
  - Feature - Toggle function - Affected operations
  
- [ ] **For each toggle:**
  - [ ] Can users exit when disabled?
  - [ ] Emergency withdraw available?
  - [ ] Pending operations handled?

### Config Change Analysis
- [ ] **List all config parameters**
  - Parameter - Setter function - Dependent state
  
- [ ] **For each parameter change:**
  - [ ] Does change update dependent state first?
  - [ ] Is there timelock for critical changes?
  - [ ] Can change be sandwiched?

### Entity Add/Remove
- [ ] **For each removable entity (token, pool, user):**
  - [ ] Is state cleaned up on removal?
  - [ ] Can users with existing positions exit?
  - [ ] What if entity is re-added?

---

## 6. EIP Compliance

### ERC-4626 Vault (if applicable)
- [ ] `maxDeposit`/`maxMint` reflect actual limits
- [ ] `maxWithdraw`/`maxRedeem` reflect actual limits
- [ ] Preview functions match execution exactly
- [ ] Rounding direction per spec
- [ ] `totalAssets` includes all assets

### ERC-20 (for any token interaction)
- [ ] SafeERC20 used for external tokens
- [ ] Fee-on-transfer handling
- [ ] Zero amount handling

### ERC-721/1155 (if applicable)
- [ ] safeTransfer checks receiver
- [ ] Approvals cleared correctly
- [ ] Batch operations validate lengths

---

## 7. Calldata Validation

### Parameter Validation
- [ ] **For functions with complex calldata:**
  - [ ] Are encoded IDs validated against explicit IDs?
  - [ ] `transform(tokenId, bytes data)` - does `data.tokenId == tokenId`?
  
- [ ] **For delegate/multicall patterns:**
  - [ ] Can user inject malicious calldata?
  - [ ] Are all calldata paths validated?

---

## Summary Finding Template

When you find an issue, document:

```markdown
### [SEVERITY]-XX: Brief Title

**Category:** [Callback Security / External Integration / Oracle / State Transition / EIP Compliance / Calldata]

**Location:** `ContractName.sol:functionName()` line XXX

**Description:** 
What's wrong and why it matters.

**Impact:**
- What can an attacker do?
- What's the worst case?

**Recommendation:**
Specific fix with code example.

**References:**
- Similar finding: [Contest-Finding-ID]
- Pattern: [pattern-file.md#section]
```

---

*Last Updated: 2026-02-04*
*Source: Revert Lend Benchmark False Negative Analysis*
