# Cryptographic Primitives Vulnerabilities

Security issues in smart contracts using elliptic curve cryptography, signature schemes, and zero-knowledge proofs.

> **Last Updated:** 2026-02-07
> **Source:** Sherlock audits, academic research, real-world exploits

---

## Overview

Cryptographic primitives in smart contracts present unique attack surfaces that require deep mathematical understanding. These vulnerabilities are often HIGH/CRITICAL severity because they can completely bypass security mechanisms.

---

## 1. BN254 (alt_bn128) Curve Issues

### 1.1 Zero Point / Point at Infinity Handling

**Description:** The point at infinity (identity element) on elliptic curves has special properties that can be exploited.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: Not checking for point at infinity
function verifySignature(
    uint256[2] memory pubkey,
    uint256[2] memory signature,
    bytes32 message
) external view returns (bool) {
    // ❌ Pubkey (0,0) or signature (0,0) may bypass verification
    return ecpairing(signature, pubkey, message);
}
```

**Attack Vector (from Symbiotic Relay Z-1):**
1. Attacker creates a validator with key (0,0) - the point at infinity
2. Point at infinity has the property: P + O = P (identity element)
3. Adding (0,0) to aggregate signature has no effect
4. Attacker can set arbitrary voting power for this null validator
5. Signature verification passes because aggregate key is unchanged

**Secure Pattern:**
```solidity
// SAFE: Validate points are not at infinity
function verifySignature(
    uint256[2] memory pubkey,
    uint256[2] memory signature,
    bytes32 message
) external view returns (bool) {
    // ✅ Check for point at infinity
    require(pubkey[0] != 0 || pubkey[1] != 0, "Invalid pubkey: point at infinity");
    require(signature[0] != 0 || signature[1] != 0, "Invalid signature");
    
    // ✅ Check point is on curve
    require(isOnCurve(pubkey[0], pubkey[1]), "Pubkey not on curve");
    
    return ecpairing(signature, pubkey, message);
}

function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
    // y² = x³ + 3 (mod p) for BN254
    uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 lhs = mulmod(y, y, p);
    uint256 rhs = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);
    return lhs == rhs;
}
```

### 1.2 Small Subgroup Attacks

**Description:** Malicious points can be chosen from small subgroups to enable key recovery or signature forgery.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: No subgroup check
function processPublicKey(uint256[2] memory point) external {
    // ❌ Point may not be in the correct subgroup
    storedKeys.push(point);
}
```

**Attack Vector:**
1. Attacker provides point in small subgroup (order < curve order)
2. After k operations with this point, information leaks
3. May allow private key recovery or signature forgery

**Secure Pattern:**
```solidity
// SAFE: Verify point is in correct subgroup
function processPublicKey(uint256[2] memory point) external {
    require(isInSubgroup(point), "Point not in prime order subgroup");
    storedKeys.push(point);
}

function isInSubgroup(uint256[2] memory point) internal view returns (bool) {
    // Multiply by curve order - should give point at infinity
    uint256 curveOrder = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256[2] memory result = ecMul(point, curveOrder);
    return result[0] == 0 && result[1] == 0;
}
```

### 1.3 Low Order Point Attacks

**Description:** Special low-order points can cause operations to fail or produce predictable results.

**Vulnerable Code:**
```solidity
// VULNERABLE: Using point without order check
function deriveSharedSecret(
    uint256[2] memory theirPubkey,
    uint256 myPrivkey
) external view returns (uint256[2] memory) {
    // ❌ If theirPubkey is low order, result is predictable
    return ecMul(theirPubkey, myPrivkey);
}
```

---

## 2. BLS Signature Vulnerabilities

### 2.1 Rogue Key Attack

**Description:** In aggregate BLS signatures, a malicious signer can forge signatures for messages they never signed.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: Simple key aggregation
function aggregateKeys(
    uint256[4][] memory pubkeys  // G2 points
) external pure returns (uint256[4] memory) {
    uint256[4] memory aggregate;
    for (uint i = 0; i < pubkeys.length; i++) {
        // ❌ Simple addition allows rogue key attack
        aggregate = g2Add(aggregate, pubkeys[i]);
    }
    return aggregate;
}
```

**Attack Vector:**
1. Honest signer has pubkey P
2. Attacker registers pubkey P' = g^x - P (where g^x is their actual key)
3. Aggregate key = P + P' = g^x
4. Attacker alone can sign for the "aggregate"

**Secure Pattern:**
```solidity
// SAFE: Use proof of possession or key hashing
function aggregateKeysWithPoP(
    uint256[4][] memory pubkeys,
    uint256[2][] memory signatures,  // Proof of possession
    bytes32[] memory messages        // Challenge messages
) external view returns (uint256[4] memory) {
    uint256[4] memory aggregate;
    for (uint i = 0; i < pubkeys.length; i++) {
        // ✅ Verify proof of possession first
        require(
            blsVerify(pubkeys[i], signatures[i], messages[i]),
            "Invalid proof of possession"
        );
        aggregate = g2Add(aggregate, pubkeys[i]);
    }
    return aggregate;
}

// Alternative: Use hash-to-curve for key aggregation
// aggregatedKey = sum(hash(pubkey_i) * pubkey_i)
```

### 2.2 Signature Malleability

**Description:** BLS signatures can be negated while remaining valid for the same message.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: Using signature as unique identifier
mapping(bytes32 => bool) public usedSignatures;

function processSignedMessage(
    uint256[2] memory signature,
    bytes32 message
) external {
    bytes32 sigHash = keccak256(abi.encode(signature));
    require(!usedSignatures[sigHash], "Signature already used");
    usedSignatures[sigHash] = true;
    
    // ❌ Negated signature (-signature) is also valid and has different hash
}
```

**Secure Pattern:**
```solidity
// SAFE: Hash message + pubkey for uniqueness, not signature
mapping(bytes32 => bool) public usedMessages;

function processSignedMessage(
    uint256[2] memory signature,
    uint256[4] memory pubkey,
    bytes32 message
) external {
    bytes32 msgHash = keccak256(abi.encode(message, pubkey));
    require(!usedMessages[msgHash], "Message already processed");
    usedMessages[msgHash] = true;
    // ✅ Message+pubkey is unique regardless of signature form
}
```

### 2.3 Non-Signer Voting Power Manipulation

**Description:** In threshold signature schemes, non-signers may still contribute to verification in unexpected ways.

**Vulnerability Pattern (from Symbiotic Relay):**
```go
// VULNERABLE: Non-signer with null key still counts voting power
if !isNonSigner[i] {
    aggregateVotingPower += validatorData[i].VotingPower
    aggregateKey = aggregateKey + validatorData[i].Key
}
// ❌ Null key (0,0) adds 0 to aggregateKey but votingPower is added
```

**Attack Vector:**
1. Add fake validator with key (0,0) and high voting power
2. Mark them as signer (isNonSigner = false)
3. Their key contribution is 0 (identity)
4. But their voting power exceeds quorum
5. Real signers only need minimal threshold

---

## 3. ECDSA Vulnerabilities

### 3.1 Signature Replay Across Chains

**Description:** Signatures valid on one chain may be replayed on another.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: No chain ID in signature
function executeWithSignature(
    address to,
    uint256 value,
    bytes memory sig
) external {
    bytes32 hash = keccak256(abi.encode(to, value, nonce));
    address signer = ECDSA.recover(hash, sig);
    // ❌ Same signature valid on any chain
}
```

**Secure Pattern:**
```solidity
// SAFE: Include chain ID (EIP-712)
function executeWithSignature(
    address to,
    uint256 value,
    bytes memory sig
) external {
    bytes32 hash = keccak256(abi.encode(
        DOMAIN_SEPARATOR,  // Includes chainId
        to, value, nonce
    ));
    address signer = ECDSA.recover(hash, sig);
}
```

### 3.2 Missing Signature Validation

**Description:** Not checking for invalid or malformed signatures.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: No validation of recovered address
function verify(bytes32 hash, bytes memory sig) external view returns (address) {
    return ECDSA.recover(hash, sig);
    // ❌ Returns address(0) for invalid signature
}

function executeIfSigned(bytes32 hash, bytes memory sig) external {
    address signer = ECDSA.recover(hash, sig);
    // ❌ If signature invalid, signer = address(0)
    // If authorized[address(0)] is somehow true, bypasses auth
    require(authorized[signer], "Not authorized");
}
```

**Secure Pattern:**
```solidity
// SAFE: Use tryRecover and validate
function executeIfSigned(bytes32 hash, bytes memory sig) external {
    (address signer, ECDSA.RecoverError err) = ECDSA.tryRecover(hash, sig);
    require(err == ECDSA.RecoverError.NoError, "Invalid signature");
    require(signer != address(0), "Zero address signer");
    require(authorized[signer], "Not authorized");
}
```

---

## 4. Hash Function Vulnerabilities

### 4.1 Length Extension Attack (SHA-256)

**Description:** SHA-256 is vulnerable to length extension attacks when used improperly.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: Simple hash of secret + message
function createMac(bytes memory secret, bytes memory message) internal pure returns (bytes32) {
    return sha256(abi.encodePacked(secret, message));
    // ❌ Attacker can extend message without knowing secret
}
```

**Attack Vector:**
1. Attacker knows H(secret || message) and len(secret || message)
2. Can compute H(secret || message || padding || extension)
3. Without knowing the secret

**Secure Pattern:**
```solidity
// SAFE: Use HMAC construction
function createHmac(bytes memory secret, bytes memory message) internal pure returns (bytes32) {
    bytes32 opad = 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c;
    bytes32 ipad = 0x3636363636363636363636363636363636363636363636363636363636363636;
    
    bytes32 keyHash = sha256(secret);
    return sha256(abi.encodePacked(
        keyHash ^ opad,
        sha256(abi.encodePacked(keyHash ^ ipad, message))
    ));
}

// OR: Use keccak256 (sponge construction, immune to length extension)
function createMac(bytes memory secret, bytes memory message) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(secret, message));
}
```

### 4.2 Weak Randomness from Block Properties

**Description:** Using block.timestamp or blockhash for randomness is exploitable.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: Miner-manipulable randomness
function random() internal view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(
        block.timestamp,
        blockhash(block.number - 1),
        msg.sender
    )));
    // ❌ Miner can influence timestamp and blockhash
}
```

---

## 5. ZK Proof Vulnerabilities

### 5.1 Public Input Manipulation

**Description:** Attackers may provide false public inputs that the verifier doesn't validate.

**Vulnerability Pattern:**
```solidity
// VULNERABLE: No public input validation
function verifyProof(
    uint256[8] memory proof,
    uint256[] memory publicInputs
) external view returns (bool) {
    // ❌ publicInputs not validated against expected values
    return Verifier.verify(proof, publicInputs);
}
```

**Secure Pattern:**
```solidity
// SAFE: Validate public inputs
function verifyProof(
    uint256[8] memory proof,
    uint256 expectedValue,
    bytes32 expectedCommitment
) external view returns (bool) {
    uint256[] memory publicInputs = new uint256[](2);
    publicInputs[0] = expectedValue;          // ✅ Protocol controls this
    publicInputs[1] = uint256(expectedCommitment);
    
    return Verifier.verify(proof, publicInputs);
}
```

### 5.2 Groth16 Malleability

**Description:** Groth16 proofs can be manipulated to create different valid proofs for the same statement.

**Attack Vector:**
- Given proof (A, B, C), attacker can compute (A', B', C') that also verifies
- If proof uniqueness is assumed, this can break replay protection

**Mitigation:**
- Don't use proof bytes as unique identifiers
- Hash (public inputs + statement) for uniqueness

---

## 6. Precompile Gas Differences (Cross-Chain)

### 6.1 Hardcoded Gas Limits

**Description:** Gas costs for ECC precompiles vary across chains, breaking contracts with hardcoded limits.

**Vulnerability Pattern (from Symbiotic Relay M-6):**
```solidity
// VULNERABLE: Hardcoded gas for ecPairing
uint256 constant PAIRING_CHECK_GAS = 120_000;  // EIP-1108 for k=2

function verify(...) internal view returns (bool) {
    assembly {
        success := staticcall(PAIRING_CHECK_GAS, 8, input, size, out, 32)
    }
    // ❌ Fails on zkSync (requires 160_000 for k=2)
}
```

**Chain-Specific Gas Costs (ecPairing k=2):**
| Chain | Gas Cost | Standard |
|-------|----------|----------|
| Ethereum | 120,000 | EIP-1108 |
| zkSync Era | 160,000 | ZIP-11 V28 |
| Arbitrum | 120,000 | EIP-1108 |
| Optimism | 120,000 | EIP-1108 |

**Secure Pattern:**
```solidity
// SAFE: Configurable gas limit
uint256 public pairingGasLimit = 120_000;

function setPairingGasLimit(uint256 newLimit) external onlyOwner {
    require(newLimit >= 100_000 && newLimit <= 500_000, "Invalid gas limit");
    pairingGasLimit = newLimit;
}

function verify(...) internal view returns (bool) {
    assembly {
        success := staticcall(sload(pairingGasLimit.slot), 8, input, size, out, 32)
    }
}
```

---

## 7. Audit Checklist

### 7.1 Elliptic Curve Operations
- [ ] Point at infinity handled correctly?
- [ ] Points validated to be on curve?
- [ ] Subgroup membership verified?
- [ ] Low-order point attacks considered?

### 7.2 BLS Signatures
- [ ] Rogue key attack mitigated (PoP or key hashing)?
- [ ] Signature malleability considered?
- [ ] Non-signer voting power correctly excluded?
- [ ] Null key (0,0) checked and rejected?

### 7.3 ECDSA
- [ ] Chain ID included in signed messages?
- [ ] Invalid signature returns handled?
- [ ] address(0) signer rejected?
- [ ] Nonce replay protection?

### 7.4 Hash Functions
- [ ] Length extension attack considered (if SHA-256)?
- [ ] Randomness not from block properties?
- [ ] Collision resistance requirements met?

### 7.5 ZK Proofs
- [ ] Public inputs validated by contract?
- [ ] Proof uniqueness not assumed?
- [ ] Verifier circuit matches expected constraints?

### 7.6 Cross-Chain
- [ ] Precompile gas limits configurable?
- [ ] Precompile availability checked per chain?
- [ ] L2-specific ECC implementations considered?

---

## References

1. Symbiotic Relay Z-1: Null key proof forgery (2025)
2. Symbiotic Relay M-6: BlsBn254 zkSync gas issue (2025)
3. "Rogue Key Attacks on BLS Signatures" - Ristenpart & Yilek
4. EIP-1108: Reduce alt_bn128 precompile gas costs
5. zkSync ZIP-11: V28 Precompile Upgrade (May 2025)
6. "Breaking the ECDSA Signature Scheme" - Breitner & Heninger

---

*This document is part of the Smart Contract Auditor vulnerability knowledge base.*
