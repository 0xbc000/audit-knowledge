"""
Slither Custom Detector: Emerging Protocol Vulnerabilities

Detects vulnerabilities specific to emerging protocol types:
- Restaking (EigenLayer/Symbiotic patterns)
- Intent-Based Systems (CoW/UniswapX patterns)
- Points/Airdrop Systems

Author: Smart Contract Auditor (ClawdEva)
Version: 1.0.0
Date: 2026-02-05
"""

from typing import List, Optional
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function, Contract
from slither.core.cfg.node import Node
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import HighLevelCall, InternalCall, Assignment


class RestakingSlashingRisk(AbstractDetector):
    """
    Detects slashing cascade vulnerabilities in restaking protocols.
    
    Key risks:
    - Multiple AVS using same collateral
    - Slashing not properly isolated
    - No slashing caps
    """
    
    ARGUMENT = "restaking-slashing-risk"
    HELP = "Potential slashing cascade vulnerability"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/emerging-protocols"
    WIKI_TITLE = "Restaking Slashing Cascade"
    WIKI_DESCRIPTION = """
    In restaking protocols, a single slashing event can cascade to affect multiple
    services (AVS) if the same stake is used as collateral for multiple services.
    """
    
    WIKI_RECOMMENDATION = """
    1. Implement slashing caps per AVS
    2. Track cumulative slashing across services
    3. Add circuit breakers for excessive slashing
    """
    
    # Slashing-related patterns
    SLASHING_PATTERNS = {
        "slash",
        "penalize",
        "slashing",
        "penalty",
        "punish",
        "confiscate",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            # Check if this looks like a restaking contract
            if not self._is_restaking_contract(contract):
                continue
            
            for function in contract.functions:
                if self._is_slashing_function(function):
                    issues = self._check_slashing_safety(function, contract)
                    for issue in issues:
                        info = [
                            f"Restaking Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_restaking_contract(self, contract: Contract) -> bool:
        name = contract.name.lower()
        return any(term in name for term in [
            "restaking", "eigenlayer", "avs", "operator", "delegation",
            "staking", "symbiotic", "vault"
        ])
    
    def _is_slashing_function(self, function: Function) -> bool:
        name = function.name.lower().replace("_", "")
        return any(pattern in name for pattern in self.SLASHING_PATTERNS)
    
    def _check_slashing_safety(self, function: Function, contract: Contract) -> List[str]:
        issues = []
        has_cap = False
        has_circuit_breaker = False
        tracks_cumulative = False
        
        # Check all state variables for slashing-related tracking
        for var in contract.state_variables:
            name = var.name.lower()
            if "cumulativeslash" in name or "totalslash" in name:
                tracks_cumulative = True
            if "slashingcap" in name or "maxslash" in name:
                has_cap = True
        
        # Check function for safety mechanisms
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for cap enforcement
            if "maxslash" in content or "cap" in content:
                has_cap = True
            
            # Check for circuit breaker pattern
            if "paused" in content or "emergency" in content:
                has_circuit_breaker = True
            
            # Check for cumulative tracking
            if "cumulative" in content or "+=" in content:
                if any(term in content for term in ["slash", "penalty"]):
                    tracks_cumulative = True
        
        if not has_cap:
            issues.append("no slashing cap implemented - cascade risk")
        
        if not tracks_cumulative:
            issues.append("doesn't track cumulative slashing across AVS")
        
        if not has_circuit_breaker:
            issues.append("no circuit breaker for excessive slashing")
        
        return issues


class RestakingDelegationRisk(AbstractDetector):
    """
    Detects delegation manipulation vulnerabilities:
    - Race conditions in delegation updates
    - Frontrunning operator selection
    - Withdrawal timing attacks
    """
    
    ARGUMENT = "restaking-delegation-risk"
    HELP = "Delegation manipulation vulnerability"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/emerging-protocols"
    WIKI_TITLE = "Restaking Delegation Risk"
    WIKI_DESCRIPTION = """
    Delegation mechanisms in restaking protocols can be manipulated through:
    - Frontrunning delegation changes
    - Gaming withdrawal timing
    - Operator selection manipulation
    """
    
    WIKI_RECOMMENDATION = """
    1. Add cooldown periods for delegation changes
    2. Use commit-reveal for operator selection
    3. Implement withdrawal delays with checkpoints
    """
    
    DELEGATION_PATTERNS = {
        "delegate",
        "undelegate",
        "redelegate",
        "setoperator",
        "chooseoperator",
        "selectvalidator",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_delegation_function(function):
                    issues = self._check_delegation_safety(function)
                    for issue in issues:
                        info = [
                            f"Delegation Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_delegation_function(self, function: Function) -> bool:
        name = function.name.lower().replace("_", "")
        return any(pattern in name for pattern in self.DELEGATION_PATTERNS)
    
    def _check_delegation_safety(self, function: Function) -> List[str]:
        issues = []
        has_cooldown = False
        has_timelock = False
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for cooldown mechanism
            if any(term in content for term in ["cooldown", "waitperiod", "delay"]):
                has_cooldown = True
            
            # Check for timelock
            if "block.timestamp" in content:
                if any(term in content for term in [">=", ">", "after"]):
                    has_timelock = True
        
        # Check modifiers for timing controls
        for modifier in function.modifiers:
            name = modifier.name.lower()
            if any(term in name for term in ["cooldown", "delay", "timelock"]):
                has_cooldown = True
        
        if not has_cooldown and not has_timelock:
            issues.append("no cooldown/timelock - vulnerable to frontrunning")
        
        return issues


class IntentReplayRisk(AbstractDetector):
    """
    Detects intent replay vulnerabilities in intent-based protocols.
    
    Key risks:
    - Missing nonce tracking
    - Expired intents still executable
    - Partial fill manipulation
    """
    
    ARGUMENT = "intent-replay-risk"
    HELP = "Intent may be replayed or manipulated"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/emerging-protocols"
    WIKI_TITLE = "Intent Replay Risk"
    WIKI_DESCRIPTION = """
    Intent-based protocols must prevent intent replay attacks where the same
    intent is executed multiple times or after expiration.
    """
    
    WIKI_RECOMMENDATION = """
    1. Track executed intents by hash/nonce
    2. Validate expiration timestamps
    3. Mark intents as consumed after execution
    """
    
    INTENT_PATTERNS = {
        "executeintent",
        "fillorder",
        "settleintent",
        "resolveintent",
        "executesigned",
        "fillsigned",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_intent_handler(function):
                    issues = self._check_intent_safety(function)
                    for issue in issues:
                        info = [
                            f"Intent Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_intent_handler(self, function: Function) -> bool:
        name = function.name.lower().replace("_", "")
        return any(pattern in name for pattern in self.INTENT_PATTERNS)
    
    def _check_intent_safety(self, function: Function) -> List[str]:
        issues = []
        has_nonce_check = False
        has_expiry_check = False
        marks_consumed = False
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for nonce tracking
            if "nonce" in content or "executed" in content or "consumed" in content:
                if node.contains_require_or_assert():
                    has_nonce_check = True
                if "= true" in content or "[" in content:
                    marks_consumed = True
            
            # Check for expiry validation
            if any(term in content for term in ["deadline", "expiry", "validuntil"]):
                if "block.timestamp" in content or node.contains_require_or_assert():
                    has_expiry_check = True
        
        if not has_nonce_check:
            issues.append("no nonce/consumed check - intent may be replayed")
        
        if not has_expiry_check:
            issues.append("no expiry validation - stale intents may execute")
        
        if not marks_consumed:
            issues.append("intent not marked as consumed after execution")
        
        return issues


class SolverCollusionRisk(AbstractDetector):
    """
    Detects potential solver collusion vulnerabilities:
    - No competition between solvers
    - Missing price validation
    - Solver can front-run user intents
    """
    
    ARGUMENT = "solver-collusion-risk"
    HELP = "Solver may extract value through collusion"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/emerging-protocols"
    WIKI_TITLE = "Solver Collusion Risk"
    WIKI_DESCRIPTION = """
    Solvers in intent-based systems can collude or extract value if:
    - No competitive auction for intent resolution
    - Missing price improvement requirements
    - Solver reputation not tracked
    """
    
    WIKI_RECOMMENDATION = """
    1. Implement solver competition/auction
    2. Require price improvement over market
    3. Track and penalize poor solver behavior
    """
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            if self._is_solver_contract(contract):
                issues = self._check_solver_fairness(contract)
                for issue in issues:
                    info = [
                        f"Solver Risk: {contract.name} ",
                        issue,
                        "\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _is_solver_contract(self, contract: Contract) -> bool:
        name = contract.name.lower()
        return any(term in name for term in [
            "solver", "resolver", "filler", "relayer", "settler"
        ])
    
    def _check_solver_fairness(self, contract: Contract) -> List[str]:
        issues = []
        has_auction = False
        has_price_check = False
        has_reputation = False
        
        for function in contract.functions:
            name = function.name.lower()
            
            if "auction" in name or "bid" in name or "compete" in name:
                has_auction = True
            
            if "reputation" in name or "score" in name or "slash" in name:
                has_reputation = True
            
            for node in function.nodes:
                content = str(node).lower()
                if any(term in content for term in ["minprice", "priceimprovement", "marketprice"]):
                    has_price_check = True
        
        if not has_auction:
            issues.append("no solver auction mechanism - single solver may extract value")
        
        if not has_price_check:
            issues.append("no price improvement validation")
        
        if not has_reputation:
            issues.append("no solver reputation/slashing mechanism")
        
        return issues


class PointsSybilRisk(AbstractDetector):
    """
    Detects Sybil attack vulnerabilities in points/airdrop systems:
    - No anti-Sybil measures
    - Flash loan point accumulation
    - Referral exploitation
    """
    
    ARGUMENT = "points-sybil-risk"
    HELP = "Points system vulnerable to Sybil/gaming"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/emerging-protocols"
    WIKI_TITLE = "Points System Sybil Risk"
    WIKI_DESCRIPTION = """
    Points and airdrop systems are vulnerable to:
    - Sybil attacks (multiple addresses)
    - Flash loan point accumulation
    - Referral system gaming
    """
    
    WIKI_RECOMMENDATION = """
    1. Use time-weighted balance for points
    2. Implement minimum deposit duration
    3. Cap referral rewards and verify uniqueness
    """
    
    POINTS_PATTERNS = {
        "addpoints",
        "accumulatepoints",
        "awardpoints",
        "updatepoints",
        "claimpoints",
        "refer",
        "referral",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_points_function(function):
                    issues = self._check_points_safety(function)
                    for issue in issues:
                        info = [
                            f"Points Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_points_function(self, function: Function) -> bool:
        name = function.name.lower().replace("_", "")
        return any(pattern in name for pattern in self.POINTS_PATTERNS)
    
    def _check_points_safety(self, function: Function) -> List[str]:
        issues = []
        has_time_weight = False
        has_min_duration = False
        has_cap = False
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for time-weighted accumulation
            if any(term in content for term in ["timeweight", "duration", "elapsed"]):
                has_time_weight = True
            
            # Check for minimum deposit duration
            if any(term in content for term in ["minduration", "lockperiod", "vestingstart"]):
                has_min_duration = True
            
            # Check for caps
            if any(term in content for term in ["maxpoints", "cap", "limit"]):
                has_cap = True
        
        if not has_time_weight and not has_min_duration:
            issues.append("no time-weighting - vulnerable to flash loan point farming")
        
        if "referral" in function.name.lower() and not has_cap:
            issues.append("referral rewards not capped - Sybil risk")
        
        return issues


class MerkleProofRisk(AbstractDetector):
    """
    Detects vulnerabilities in Merkle proof claim systems:
    - Missing claim tracking
    - Proof manipulation
    - Incorrect root verification
    """
    
    ARGUMENT = "merkle-proof-risk"
    HELP = "Merkle proof claim may be manipulated"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/emerging-protocols"
    WIKI_TITLE = "Merkle Proof Claim Risk"
    WIKI_DESCRIPTION = """
    Merkle proof based claim systems must:
    - Track claimed leaves to prevent double-claiming
    - Properly verify proof against root
    - Handle root updates safely
    """
    
    WIKI_RECOMMENDATION = """
    1. Use mapping to track claimed indices/addresses
    2. Verify proof includes msg.sender to prevent proof reuse
    3. Implement claim deadline
    """
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_merkle_claim(function):
                    issues = self._check_merkle_safety(function, contract)
                    for issue in issues:
                        info = [
                            f"Merkle Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_merkle_claim(self, function: Function) -> bool:
        name = function.name.lower()
        params = [p.name.lower() for p in function.parameters]
        
        return ("claim" in name or "redeem" in name) and "proof" in " ".join(params)
    
    def _check_merkle_safety(self, function: Function, contract: Contract) -> List[str]:
        issues = []
        has_claim_tracking = False
        verifies_sender = False
        
        # Check for claimed mapping
        for var in contract.state_variables:
            if "claimed" in var.name.lower() or "redeemed" in var.name.lower():
                has_claim_tracking = True
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check if proof verification includes msg.sender
            if "merkle" in content or "verify" in content:
                if "msg.sender" in content:
                    verifies_sender = True
            
            # Additional claim tracking check
            if "claimed[" in content or "redeemed[" in content:
                has_claim_tracking = True
        
        if not has_claim_tracking:
            issues.append("no claim tracking - double claim possible")
        
        if not verifies_sender:
            issues.append("proof doesn't include msg.sender - proof may be reused")
        
        return issues


# Register all detectors
DETECTORS = [
    RestakingSlashingRisk,
    RestakingDelegationRisk,
    IntentReplayRisk,
    SolverCollusionRisk,
    PointsSybilRisk,
    MerkleProofRisk,
]
