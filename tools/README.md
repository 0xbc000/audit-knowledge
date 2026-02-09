# Smart Contract Auditor - Automation Tools

This directory contains custom detectors and testing templates for automated smart contract security analysis.

## 📁 Directory Structure

```
tools/
├── slither-detectors/                  # Custom Slither detectors (31 total)
│   ├── mev_risks.py                   # MEV vulnerability detection (5)
│   ├── l2_specific.py                 # L2-specific vulnerability detection (5)
│   ├── emerging_protocols.py          # Emerging protocol pattern detection (6)
│   ├── admin_security.py              # Admin security (L2 focus) (5)
│   ├── cryptographic_primitives.py    # BN254/BLS/ZK vulnerabilities (5) ⭐ NEW
│   └── fcfs_tiering.py                # FCFS/tiering system detection (5) ⭐ NEW
├── foundry-templates/                  # Foundry invariant test templates (6 total)
│   ├── DeFiInvariantBase.sol          # Base contract with common invariants
│   ├── VaultInvariantTest.t.sol       # ERC-4626 vault testing template
│   ├── LendingInvariantTest.t.sol     # Lending protocol testing template
│   ├── AdminSecurityInvariantTest.t.sol   # Admin security invariants
│   ├── CryptographicInvariantTest.t.sol   # BN254/BLS/ZK invariants ⭐ NEW
│   └── FCFSTieringInvariantTest.t.sol     # FCFS ranking invariants ⭐ NEW
└── README.md                           # This file
```

---

## 🔍 Slither Custom Detectors

### Installation

1. Ensure Slither is installed:
   ```bash
   pip install slither-analyzer
   ```

2. Register custom detectors:
   ```bash
   # Option 1: Add to SLITHER_CUSTOM_DETECTOR_PATH
   export SLITHER_CUSTOM_DETECTOR_PATH=/path/to/tools/slither-detectors
   
   # Option 2: Use --detector-path flag
   slither . --detector-path /path/to/tools/slither-detectors
   ```

### Available Detectors

#### MEV Risks (`mev_risks.py`)

| Detector | Impact | Description |
|----------|--------|-------------|
| `mev-missing-slippage` | HIGH | Swap functions without slippage protection |
| `mev-excessive-slippage` | MEDIUM | Slippage tolerance > 5% |
| `mev-missing-deadline` | MEDIUM | Missing deadline check in swaps |
| `mev-flash-loan-enabler` | HIGH | Functions that may enable flash loan attacks |
| `mev-oracle-manipulation` | HIGH | Oracle manipulation vulnerabilities |

**Usage:**
```bash
slither . --detect mev-missing-slippage,mev-oracle-manipulation
```

#### L2 Specific (`l2_specific.py`)

| Detector | Impact | Description |
|----------|--------|-------------|
| `l2-sequencer-dependency` | HIGH | Operations vulnerable to sequencer downtime |
| `l2-message-risk` | HIGH | L1<->L2 message handling vulnerabilities |
| `l2-address-aliasing` | HIGH | Address aliasing not handled |
| `l2-gas-calculation` | MEDIUM | L2 gas calculation issues |
| `l2-reorg-risk` | MEDIUM | Operations affected by L2 reorgs |

**Usage:**
```bash
slither . --detect l2-sequencer-dependency,l2-address-aliasing
```

#### Emerging Protocols (`emerging_protocols.py`)

| Detector | Impact | Description |
|----------|--------|-------------|
| `restaking-slashing-risk` | HIGH | Slashing cascade vulnerabilities |
| `restaking-delegation-risk` | MEDIUM | Delegation manipulation |
| `intent-replay-risk` | HIGH | Intent replay vulnerabilities |
| `solver-collusion-risk` | HIGH | Solver MEV extraction |
| `points-sybil-risk` | HIGH | Sybil attack vulnerabilities |
| `merkle-proof-risk` | HIGH | Merkle proof claim issues |

**Usage:**
```bash
slither . --detect restaking-slashing-risk,intent-replay-risk
```

#### Admin Security (`admin_security.py`) ⭐ NEW

Based on real exploits like USDGambit/TLP ($1.5M, Jan 2026).

| Detector | Impact | Description |
|----------|--------|-------------|
| `admin-upgrade-no-timelock` | HIGH | Proxy upgrade without timelock protection |
| `admin-shared-deployer` | HIGH | Deployer as admin - single point of failure |
| `l2-bridge-exit-risk` | HIGH | Admin can drain via L2→L1 bridge |
| `admin-emergency-withdraw` | HIGH | Emergency withdraw may steal user funds |
| `admin-multisig-bypass` | HIGH | Multi-sig protection may be bypassable |

**Usage:**
```bash
slither . --detect admin-upgrade-no-timelock,l2-bridge-exit-risk

# L2-focused admin security audit
slither . --detect admin-upgrade-no-timelock,l2-bridge-exit-risk,admin-shared-deployer
```

**Critical for L2 Protocols:**
- Upgrade delay MUST be > 7 days (Arbitrum/Optimism bridge delay)
- Admin key compromise + instant upgrade = total fund loss
- Monitor L1 for upgrade proposals

#### Cryptographic Primitives (`cryptographic_primitives.py`) ⭐ NEW

Based on Symbiotic Relay vulnerabilities (Sherlock 2026).

| Detector | Impact | Description |
|----------|--------|-------------|
| `crypto-bn254-zero-point` | CRITICAL | BN254/BLS zero point (0,0) bypass |
| `crypto-rogue-key` | HIGH | Missing proof-of-possession for BLS keys |
| `crypto-sig-malleability` | MEDIUM | ECDSA s-value not in lower half |
| `crypto-zk-verification-gap` | HIGH | ZK proof verification may have gaps |
| `crypto-precompile-gas-l2` | MEDIUM | ECC precompiles have higher costs on L2 |

**Usage:**
```bash
slither . --detect crypto-bn254-zero-point,crypto-rogue-key

# Full cryptographic audit
slither . --detect crypto-bn254-zero-point,crypto-rogue-key,crypto-sig-malleability,crypto-zk-verification-gap
```

**Key Vulnerability (Z-1 from Symbiotic Relay):**
- BN254 zero point (0,0) is the identity element
- Aggregating with zero point doesn't change the aggregate
- Attacker can submit (0,0) as public key and forge valid signatures
- **Fix:** Always check `require(point.x != 0 || point.y != 0)`

#### FCFS Tiering (`fcfs_tiering.py`) ⭐ NEW

Based on LayerEdge vulnerabilities (Sherlock 2026).

| Detector | Impact | Description |
|----------|--------|-------------|
| `fcfs-tier-boundary` | HIGH | Integer division edge cases in tier boundaries |
| `fcfs-ghost-staker` | HIGH | Zero-amount staking creates ghost entries |
| `fcfs-cascade-dos` | HIGH | O(k × log n) gas exhaustion in tier updates |
| `fcfs-position-gaming` | MEDIUM | Ranking vulnerable to gaming |
| `fcfs-fenwick-consistency` | HIGH | Fenwick tree may become inconsistent |

**Usage:**
```bash
slither . --detect fcfs-tier-boundary,fcfs-ghost-staker

# Full FCFS/tiering audit
slither . --detect fcfs-tier-boundary,fcfs-ghost-staker,fcfs-cascade-dos,fcfs-fenwick-consistency
```

**Key Vulnerability (H-2, H-7 from LayerEdge):**
- At specific staker counts (10N+4 pattern: 14, 24, 34...),
  integer division causes tier boundaries to collide
- Example: 14 stakers with 40%/30%/30% split
  - tier1Boundary = 14 * 40 / 100 = 5
  - tier2Boundary = 14 * 70 / 100 = 9
  - Stakers at ranks 6-9 get wrong tier assignment

### Run All Custom Detectors

```bash
slither . --detector-path /path/to/tools/slither-detectors
```

---

## 🧪 Foundry Invariant Templates

### Installation

1. Copy templates to your Foundry project:
   ```bash
   cp -r tools/foundry-templates/* your-project/test/invariants/
   ```

2. Import the base contract in your tests:
   ```solidity
   import "test/invariants/DeFiInvariantBase.sol";
   ```

### Available Templates

#### `DeFiInvariantBase.sol`

Base contract with common DeFi invariant checks:

- **AccountingInvariants**: Total supply, deposit/withdraw balance
- **AccessControlInvariants**: Admin checks, role protection
- **VaultInvariants**: ERC-4626 specific (share value, preview functions)
- **LendingInvariants**: Utilization, collateral ratios, interest rates
- **DEXInvariants**: Constant product, swap output, LP value

#### `VaultInvariantTest.t.sol`

Complete ERC-4626 vault invariant test with:

- Total shares match user balances
- Total assets match underlying balance
- No share value inflation
- Conversion consistency
- Preview function accuracy
- First depositor attack protection

**Customization:**
1. Replace `IVault` with your vault interface
2. Deploy your vault in `setUp()`
3. Add protocol-specific invariants

#### `LendingInvariantTest.t.sol`

Lending protocol invariant test with:

- Utilization bounded
- All positions collateralized
- Interest indices monotonic
- Deposits exceed borrows
- No unsecured debt
- Bad debt isolation
- Interest rates bounded
- Reserve accounting

**Customization:**
1. Replace `ILendingPool` with your lending interface
2. Deploy your lending pool in `setUp()`
3. Adjust constants (LTV, liquidation threshold)
4. Add protocol-specific invariants

#### `AdminSecurityInvariantTest.t.sol` ⭐ NEW

Admin security invariant test based on real exploits (USDGambit/TLP $1.5M):

- **Admin change invariants**: Two-step transfer, delay enforcement
- **Upgrade invariants**: Minimum delay, delay > L2 bridge delay (7 days)
- **Multi-sig invariants**: Threshold ≥ 2, minimum owner count
- **Withdrawal invariants**: Daily limits, large withdrawal delays
- **Composite invariant**: No instant drain + bridge exit attack

Includes `L2AdminSecurityInvariantTest` extension with L2-specific checks:
- Upgrade delay > 7 days (Arbitrum/Optimism challenge period)
- Admin delay > 7 days
- Sequencer-independent emergency functions

**Customization:**
1. Replace interfaces with your protocol's admin contracts
2. Deploy your contracts in `setUp()`
3. Adjust `minRequiredThreshold` based on TVL
4. For L2: ensure delays exceed bridge withdrawal delay

#### `CryptographicInvariantTest.t.sol` ⭐ NEW

Cryptographic primitives invariant test based on Symbiotic Relay (Sherlock 2026):

- **BN254/BLS Zero Point Invariants**:
  - No registered key is the zero/identity point (0,0)
  - Aggregate key never zero when keys registered
  - Points verified on BN254 curve

- **Rogue Key Attack Invariants**:
  - All keys have proof-of-possession verified
  
- **Signature Malleability Invariants**:
  - ECDSA s-value in lower half of curve order
  - BN254 signature components within valid range

- **L2 Extension (zkSync)**:
  - ECC precompile gas limits (ECADD 10K, ECMUL 40K, ECPAIRING 600K+)
  - Batch verification stays within block limits

**Key Invariant:**
```solidity
function invariant_noZeroPointKeys() public view {
    for (uint256 i = 0; i < registeredAddresses.length; i++) {
        uint256[2] memory key = registeredKeys[registeredAddresses[i]];
        bool isZeroPoint = (key[0] == 0 && key[1] == 0);
        assertTrue(!isZeroPoint, "Zero point key - signature bypass possible");
    }
}
```

#### `FCFSTieringInvariantTest.t.sol` ⭐ NEW

FCFS and tiering system invariant test based on LayerEdge (Sherlock 2026):

- **Tier Boundary Invariants**:
  - Boundaries strictly increasing
  - Tier sum equals total stakers
  - Edge case handling (10N+4 pattern)

- **Ghost Staker Invariants**:
  - All ranked stakers have minimum stake
  - No zero-stake ranking entries
  - Minimum stake enforced (> 0)

- **Ranking Tree Consistency**:
  - Tree size matches staker count
  - Each staker in tree exactly once
  - Ranks unique and contiguous

- **Gas/DoS Invariants**:
  - Stake operation gas bounded
  - Tier calculation O(1) or O(log n)

**Key Invariant:**
```solidity
function invariant_tierBoundariesConsistent() public view {
    uint256 total = staking.totalStakers();
    uint256 tier1Boundary = staking.getTierBoundary(1);
    uint256 tier2Boundary = staking.getTierBoundary(2);
    
    assertTrue(tier1Boundary < tier2Boundary, "Tier boundaries not increasing");
    assertTrue(tier2Boundary <= total, "Tier 2 boundary exceeds total");
}
```

### Running Invariant Tests

```bash
# Run all invariant tests
forge test --match-test invariant

# Run with specific depth and runs
forge test --match-test invariant --fuzz-runs 1000 --fuzz-depth 100

# Run with verbosity
forge test --match-test invariant -vvv
```

### Best Practices

1. **Start with fewer runs, increase gradually**
   ```bash
   forge test --fuzz-runs 100    # Quick smoke test
   forge test --fuzz-runs 10000  # Thorough testing
   ```

2. **Use call summaries to verify coverage**
   - Check that all handler functions are being called
   - Adjust bounds if some functions are skipped

3. **Add protocol-specific invariants**
   - Token-specific checks (rebasing, fee-on-transfer)
   - Protocol-specific business logic
   - Time-dependent invariants

4. **Test with different actor configurations**
   - Single actor (simplest case)
   - Multiple actors (more realistic)
   - Admin + users (access control)

---

## 📚 Additional Resources

- [Slither Documentation](https://github.com/crytic/slither)
- [Foundry Invariant Testing](https://book.getfoundry.sh/forge/invariant-testing)
- [Writing Custom Slither Detectors](https://github.com/crytic/slither/wiki/Adding-a-new-detector)

---

## 🔄 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-05 | Initial release with MEV, L2, and emerging protocol detectors |
| 1.1.0 | 2026-02-06 | Added admin_security.py (5 detectors) and AdminSecurityInvariantTest.t.sol |
| 1.2.0 | 2026-02-07 | Added cryptographic_primitives.py (5 detectors) + fcfs_tiering.py (5 detectors); CryptographicInvariantTest.t.sol + FCFSTieringInvariantTest.t.sol |

---

## 📊 Statistics

| Category | Count |
|----------|-------|
| **Slither Detectors** | 31 |
| **Foundry Templates** | 6 |
| **Total Code** | ~180KB |

---

*Created by Smart Contract Auditor (ClawdEva) - Part of the nightly improvement initiative*
