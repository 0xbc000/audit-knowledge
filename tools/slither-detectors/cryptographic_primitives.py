"""
Cryptographic Primitives Vulnerability Detectors for Slither

Based on real vulnerabilities from:
- Symbiotic Relay (Sherlock, 2026): BN254/BLS zero point bypass
- Various ZK protocol audits

Detects:
1. BN254/BLS zero point acceptance (null key bypass)
2. Missing rogue key attack protection
3. Signature malleability vulnerabilities
4. ZK proof verification gaps
5. Precompile gas exhaustion on L2

Author: Smart Contract Auditor (ClawdEva)
Date: 2026-02-07
"""

from typing import List
from slither.core.declarations import Function, Contract
from slither.core.cfg.node import Node
from slither.core.expressions import CallExpression, Identifier
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output


class BN254ZeroPointDetector(AbstractDetector):
    """
    Detects acceptance of BN254/BLS zero points (0,0) which can bypass signature verification.
    
    From Symbiotic Relay Z-1:
    - Zero point (0,0) is the identity element
    - Aggregating with zero point doesn't change the aggregate
    - Attacker can forge proofs with null keys
    """
    
    ARGUMENT = "crypto-bn254-zero-point"
    HELP = "BN254/BLS zero point (0,0) may bypass signature verification"
    IMPACT = DetectorClassification.CRITICAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#crypto-bn254-zero-point"
    WIKI_TITLE = "BN254 Zero Point Vulnerability"
    WIKI_DESCRIPTION = "Functions accepting BN254 points without checking for zero/identity point"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function verifySignature(
    uint256[2] memory publicKey,  // Can be (0,0) - identity element
    uint256[4] memory signature
) external returns (bool) {
    // Missing: require(publicKey[0] != 0 || publicKey[1] != 0, "null key");
    return BN254.verify(publicKey, message, signature);
}
```
Attacker submits (0,0) as public key, forging valid signatures.
"""
    WIKI_RECOMMENDATION = """
Always validate that BN254 points are not the identity element:
```solidity
require(point.x != 0 || point.y != 0, "Invalid zero point");
```
For G1 points: (0, 0) is identity
For G2 points: ((0, 0), (0, 0)) is identity
"""

    # Patterns indicating BN254/BLS usage
    CRYPTO_PATTERNS = [
        "bn254", "bls", "g1point", "g2point", "pairing",
        "verifysignature", "verifyproof", "aggregate",
        "ecadd", "ecmul", "ecpairing"
    ]
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                # Check if function handles cryptographic operations
                if not self._handles_crypto(function):
                    continue
                
                # Check for zero point validation
                if not self._has_zero_check(function):
                    info = [
                        function,
                        " handles BN254/BLS points but may not validate against zero point (0,0)\n",
                        "Zero point is the identity element and can bypass signature verification\n"
                    ]
                    
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _handles_crypto(self, function: Function) -> bool:
        """Check if function handles cryptographic operations"""
        # Check function name
        func_name = function.name.lower()
        if any(pattern in func_name for pattern in self.CRYPTO_PATTERNS):
            return True
        
        # Check for uint256[2] or uint256[4] parameters (common point representations)
        for param in function.parameters:
            param_type = str(param.type).lower()
            if "uint256[2]" in param_type or "uint256[4]" in param_type:
                if any(kw in param.name.lower() for kw in ["key", "point", "sig", "pub", "g1", "g2"]):
                    return True
        
        # Check internal calls for crypto operations
        for call in function.internal_calls:
            if hasattr(call, 'name'):
                call_name = call.name.lower() if isinstance(call.name, str) else str(call.name).lower()
                if any(pattern in call_name for pattern in self.CRYPTO_PATTERNS):
                    return True
        
        return False
    
    def _has_zero_check(self, function: Function) -> bool:
        """Check if function validates against zero point"""
        source = function.source_mapping.content if hasattr(function.source_mapping, 'content') else ""
        
        # Look for zero checks in source
        zero_patterns = [
            "!= 0", "!= 0x0", "!= address(0)",
            "> 0", "point.x != 0", "point.y != 0",
            "require(.*key.*!= 0", "require(.*point.*!= 0"
        ]
        
        for node in function.nodes:
            node_str = str(node).lower()
            for pattern in zero_patterns:
                if pattern.lower() in node_str:
                    return True
        
        return False


class RogueKeyAttackDetector(AbstractDetector):
    """
    Detects missing rogue key attack protection in BLS aggregate signatures.
    
    Rogue key attack: Attacker generates key k' = k - Σ(other_keys) so that
    aggregate key becomes just their key, allowing signature forgery.
    """
    
    ARGUMENT = "crypto-rogue-key"
    HELP = "Missing proof-of-possession for BLS key registration"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#crypto-rogue-key"
    WIKI_TITLE = "Rogue Key Attack Vulnerability"
    WIKI_DESCRIPTION = "BLS key registration without proof-of-possession enables rogue key attacks"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function registerKey(uint256[2] memory publicKey) external {
    keys[msg.sender] = publicKey;  // No proof-of-possession!
}
```
Attacker registers k' = k - Σ(other_keys), making aggregate = their key only.
"""
    WIKI_RECOMMENDATION = """
Require proof-of-possession when registering BLS keys:
```solidity
function registerKey(
    uint256[2] memory publicKey,
    uint256[4] memory proofOfPossession  // Signature of (publicKey, msg.sender)
) external {
    require(BLS.verify(publicKey, hash(publicKey, msg.sender), proofOfPossession));
    keys[msg.sender] = publicKey;
}
```
"""
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                # Check if function registers keys
                if not self._is_key_registration(function):
                    continue
                
                # Check for proof-of-possession
                if not self._has_pop_verification(function):
                    info = [
                        function,
                        " registers BLS/BN254 keys without proof-of-possession\n",
                        "This enables rogue key attacks on aggregate signatures\n"
                    ]
                    
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _is_key_registration(self, function: Function) -> bool:
        """Check if function registers cryptographic keys"""
        func_name = function.name.lower()
        registration_patterns = ["register", "setkey", "addkey", "updatekey", "setpublic"]
        
        if any(pattern in func_name for pattern in registration_patterns):
            # Check for key-related parameters
            for param in function.parameters:
                if any(kw in param.name.lower() for kw in ["key", "pubkey", "public", "g1", "g2"]):
                    return True
        
        return False
    
    def _has_pop_verification(self, function: Function) -> bool:
        """Check if function verifies proof-of-possession"""
        for node in function.nodes:
            node_str = str(node).lower()
            if any(pattern in node_str for pattern in ["verify", "proof", "signature", "pop"]):
                return True
        
        # Check for signature parameter
        for param in function.parameters:
            if any(kw in param.name.lower() for kw in ["proof", "signature", "pop", "attestation"]):
                return True
        
        return False


class SignatureMalleabilityDetector(AbstractDetector):
    """
    Detects signature malleability vulnerabilities (ECDSA s-value not restricted).
    """
    
    ARGUMENT = "crypto-sig-malleability"
    HELP = "ECDSA signature may be malleable (s-value not restricted to lower half)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#crypto-sig-malleability"
    WIKI_TITLE = "Signature Malleability"
    WIKI_DESCRIPTION = "ECDSA signatures can be malleable if s-value is not restricted"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    address signer = ecrecover(hash, v, r, s);  // Malleable!
    require(signer == expected);
}
```
Attacker can create second valid signature: (v', r, n - s) where n is curve order.
"""
    WIKI_RECOMMENDATION = """
Use OpenZeppelin's ECDSA library or enforce s in lower half:
```solidity
uint256 constant SECP256K1_N_DIV_2 = 0x7FFFFFFF...;
require(uint256(s) <= SECP256K1_N_DIV_2, "Invalid s-value");
```
"""
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                for node in function.nodes:
                    # Look for ecrecover calls
                    if "ecrecover" in str(node).lower():
                        # Check for s-value validation
                        if not self._has_malleability_check(function):
                            info = [
                                node,
                                " uses ecrecover without s-value malleability protection\n"
                            ]
                            
                            res = self.generate_result(info)
                            results.append(res)
        
        return results
    
    def _has_malleability_check(self, function: Function) -> bool:
        """Check for s-value bounds checking"""
        for node in function.nodes:
            node_str = str(node).lower()
            # Check for s-value validation patterns
            if "s <" in node_str or "s <=" in node_str:
                return True
            if "secp256k1" in node_str and "div" in node_str:
                return True
            # Check for OpenZeppelin ECDSA usage
            if "ecdsa.recover" in node_str or "ecdsa.tryrecover" in node_str:
                return True
        
        return False


class ZKProofVerificationGapDetector(AbstractDetector):
    """
    Detects potential ZK proof verification gaps.
    """
    
    ARGUMENT = "crypto-zk-verification-gap"
    HELP = "ZK proof verification may have gaps"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#crypto-zk-verification-gap"
    WIKI_TITLE = "ZK Proof Verification Gap"
    WIKI_DESCRIPTION = "ZK proof verification that may not cover all cases"
    WIKI_RECOMMENDATION = "Ensure ZK verifier validates all public inputs and proof components"
    
    ZK_PATTERNS = ["verify", "proof", "groth16", "plonk", "snark", "stark"]
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if not self._handles_zk(function):
                    continue
                
                # Check for proper verification
                issues = self._check_verification_completeness(function)
                for issue in issues:
                    info = [function, f" {issue}\n"]
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _handles_zk(self, function: Function) -> bool:
        """Check if function handles ZK proofs"""
        func_name = function.name.lower()
        if any(pattern in func_name for pattern in self.ZK_PATTERNS):
            return True
        
        for param in function.parameters:
            if "proof" in param.name.lower():
                return True
        
        return False
    
    def _check_verification_completeness(self, function: Function) -> List[str]:
        """Check for verification gaps"""
        issues = []
        
        has_return_check = False
        has_revert = False
        
        for node in function.nodes:
            node_str = str(node).lower()
            if "require" in node_str and "verify" in node_str:
                has_return_check = True
            if "revert" in node_str:
                has_revert = True
        
        if not has_return_check and not has_revert:
            issues.append("ZK verification result may not be checked")
        
        return issues


class PrecompileGasExhaustionDetector(AbstractDetector):
    """
    Detects cryptographic operations that may exceed gas limits on L2s.
    
    From Symbiotic Relay M-6:
    - BlsBn254 operations failed on zkSync due to different gas costs
    - ECC precompiles have different costs on different L2s
    """
    
    ARGUMENT = "crypto-precompile-gas-l2"
    HELP = "Cryptographic precompile may exceed gas limits on some L2s"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#crypto-precompile-gas-l2"
    WIKI_TITLE = "Precompile Gas Exhaustion on L2"
    WIKI_DESCRIPTION = "ECC precompile operations may have different gas costs on L2s"
    WIKI_EXPLOIT_SCENARIO = """
From Symbiotic Relay M-6 (zkSync V28):
- ECADD: 500 gas on mainnet → 10,000 on zkSync
- ECMUL: 6,000 gas on mainnet → 40,000 on zkSync
- ECPAIRING: 113,000 gas on mainnet → 600,000+ on zkSync

Operations that work on L1 may fail on L2 due to gas limits.
"""
    WIKI_RECOMMENDATION = """
1. Test on all target L2s
2. Add L2-specific gas buffers
3. Consider batching or off-chain computation
4. Check L2 precompile documentation
"""
    
    ECC_PRECOMPILES = ["ecadd", "ecmul", "ecpairing", "ecrecover", "modexp"]
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                precompile_uses = self._count_precompile_uses(function)
                
                if precompile_uses > 0:
                    info = [
                        function,
                        f" uses {precompile_uses} ECC precompile(s) which may have higher gas costs on L2\n",
                        "Consider L2-specific gas testing\n"
                    ]
                    
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _count_precompile_uses(self, function: Function) -> int:
        """Count ECC precompile usages"""
        count = 0
        
        for node in function.nodes:
            node_str = str(node).lower()
            for precompile in self.ECC_PRECOMPILES:
                if precompile in node_str:
                    count += 1
        
        return count


# =============================================================================
# DETECTOR REGISTRATION
# =============================================================================

DETECTORS = [
    BN254ZeroPointDetector,
    RogueKeyAttackDetector,
    SignatureMalleabilityDetector,
    ZKProofVerificationGapDetector,
    PrecompileGasExhaustionDetector,
]
