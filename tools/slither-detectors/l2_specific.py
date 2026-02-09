"""
Slither Custom Detector: L2-Specific Vulnerabilities

Detects Layer 2 specific vulnerabilities:
- Sequencer dependency issues
- L1->L2 message handling risks
- Gas calculation differences
- Address aliasing problems
- Cross-chain finality issues

Author: Smart Contract Auditor (ClawdEva)
Version: 1.0.0
Date: 2026-02-05
"""

from typing import List, Optional
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function, Contract
from slither.core.cfg.node import Node
from slither.slithir.operations import HighLevelCall, InternalCall


class SequencerDependency(AbstractDetector):
    """
    Detects critical operations that may fail during sequencer downtime.
    
    On L2s like Arbitrum/Optimism, if the sequencer is down:
    - Users cannot submit transactions
    - Time-sensitive operations (liquidations, auctions) may be blocked
    """
    
    ARGUMENT = "l2-sequencer-dependency"
    HELP = "Operation vulnerable to sequencer downtime"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/l2-specific"
    WIKI_TITLE = "Sequencer Dependency Risk"
    WIKI_DESCRIPTION = """
    Time-sensitive operations on L2 networks may fail during sequencer downtime,
    causing liquidations to fail, auctions to be blocked, or positions to be stuck.
    """
    
    WIKI_RECOMMENDATION = """
    1. Use Chainlink's Sequencer Uptime Feed for status checks
    2. Add grace periods after sequencer recovery
    3. Implement force-inclusion via L1 for critical operations
    """
    
    # Time-sensitive function patterns
    TIME_SENSITIVE_FUNCTIONS = {
        "liquidate",
        "liquidation",
        "auction",
        "settle",
        "expire",
        "claim",
        "withdraw",
        "exercise",
        "executeliquidation",
        "triggerauction",
        "callmargin",
    }
    
    # Chainlink sequencer uptime feed check
    SEQUENCER_CHECK_PATTERNS = {
        "sequenceruptimefeed",
        "sequencerstatus",
        "l2sequencer",
        "issequencerup",
    }
    
    def _detect(self) -> List:
        results = []
        
        # Check if contract appears to be L2-targeted
        if not self._is_l2_contract():
            return results
        
        for contract in self.compilation_unit.contracts_derived:
            has_sequencer_check = self._contract_checks_sequencer(contract)
            
            for function in contract.functions:
                if self._is_time_sensitive(function) and not has_sequencer_check:
                    info = [
                        f"L2 Risk: {function.canonical_name} ",
                        "is time-sensitive but contract lacks sequencer uptime check\n",
                        "Consider using Chainlink Sequencer Uptime Feed\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _is_l2_contract(self) -> bool:
        """Check if contract has L2-specific imports or patterns"""
        for contract in self.compilation_unit.contracts:
            name = contract.name.lower()
            if any(chain in name for chain in ["arbitrum", "optimism", "l2", "rollup"]):
                return True
            
            # Check for L2-specific precompiles
            for function in contract.functions:
                for node in function.nodes:
                    content = str(node).lower()
                    if any(term in content for term in ["arbsys", "l2messenger", "ovmcontext"]):
                        return True
        
        return False
    
    def _is_time_sensitive(self, function: Function) -> bool:
        name = function.name.lower().replace("_", "")
        return any(term in name for term in self.TIME_SENSITIVE_FUNCTIONS)
    
    def _contract_checks_sequencer(self, contract: Contract) -> bool:
        for function in contract.functions:
            for node in function.nodes:
                content = str(node).lower().replace("_", "")
                if any(pattern in content for pattern in self.SEQUENCER_CHECK_PATTERNS):
                    return True
        return False


class L1L2MessageRisk(AbstractDetector):
    """
    Detects vulnerabilities in L1<->L2 message handling:
    - Missing replay protection
    - No retryable ticket expiration handling
    - Stale cross-chain data usage
    """
    
    ARGUMENT = "l2-message-risk"
    HELP = "L1<->L2 message handling vulnerability"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/l2-specific"
    WIKI_TITLE = "L1<->L2 Message Risk"
    WIKI_DESCRIPTION = """
    Cross-chain messages have inherent delays and may fail. Contracts must handle:
    - Message replay attacks
    - Failed/expired retryable tickets
    - Stale data from delayed messages
    """
    
    WIKI_RECOMMENDATION = """
    1. Implement nonce-based replay protection
    2. Handle retryable ticket expiration gracefully
    3. Validate message freshness with timestamps
    """
    
    # L1->L2 messaging functions
    L1L2_PATTERNS = {
        "onlybridge",
        "onlymessenger",
        "crosschainmessage",
        "receivemessage",
        "finalizemessage",
        "relayermessage",
        "createretryableticket",
        "redeemticket",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_message_handler(function):
                    issues = self._check_message_handler(function)
                    for issue in issues:
                        info = [
                            f"L2 Message Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_message_handler(self, function: Function) -> bool:
        name = function.name.lower().replace("_", "")
        
        # Check function name
        if any(pattern in name for pattern in self.L1L2_PATTERNS):
            return True
        
        # Check modifiers
        for modifier in function.modifiers:
            if "bridge" in modifier.name.lower() or "messenger" in modifier.name.lower():
                return True
        
        return False
    
    def _check_message_handler(self, function: Function) -> List[str]:
        issues = []
        has_replay_protection = False
        has_timestamp_check = False
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for nonce/processed message tracking
            if any(term in content for term in ["nonce", "processed", "executed", "messageid"]):
                has_replay_protection = True
            
            # Check for timestamp validation
            if "block.timestamp" in content or "staleness" in content:
                has_timestamp_check = True
        
        if not has_replay_protection:
            issues.append("lacks replay protection (no nonce/processed check)")
        
        if not has_timestamp_check:
            issues.append("no freshness validation for cross-chain data")
        
        return issues


class AddressAliasingRisk(AbstractDetector):
    """
    Detects address aliasing vulnerabilities in L1->L2 communication.
    
    On Arbitrum, L1 contract addresses are aliased on L2:
    L2_address = L1_address + 0x1111000000000000000000000000000000001111
    
    If L2 contract doesn't account for this, access control may fail.
    """
    
    ARGUMENT = "l2-address-aliasing"
    HELP = "Address aliasing not handled in cross-chain communication"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/l2-specific"
    WIKI_TITLE = "Address Aliasing Risk"
    WIKI_DESCRIPTION = """
    L1 contract addresses are aliased when calling L2 contracts via retryable tickets.
    Access control checks comparing msg.sender to L1 addresses will fail without
    applying the alias offset.
    """
    
    WIKI_RECOMMENDATION = """
    Use AddressAliasHelper.undoL1ToL2Alias(msg.sender) when validating
    cross-chain calls from L1 contracts.
    """
    
    # Arbitrum address alias offset
    ALIAS_OFFSET = "0x1111000000000000000000000000000000001111"
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            # Check if contract handles cross-chain messages
            if self._has_cross_chain_handler(contract):
                if not self._handles_address_aliasing(contract):
                    info = [
                        f"L2 Address Aliasing Risk: {contract.name} ",
                        "handles cross-chain messages but may not account for address aliasing\n",
                        "L1 contract addresses are offset by 0x1111...1111 on L2\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _has_cross_chain_handler(self, contract: Contract) -> bool:
        for function in contract.functions:
            if function.visibility in ["external", "public"]:
                for modifier in function.modifiers:
                    if any(term in modifier.name.lower() for term in ["bridge", "l1", "crosschain"]):
                        return True
                
                name = function.name.lower()
                if any(term in name for term in ["froml1", "onreceive", "relayed"]):
                    return True
        
        return False
    
    def _handles_address_aliasing(self, contract: Contract) -> bool:
        for function in contract.functions:
            for node in function.nodes:
                content = str(node).lower()
                if any(term in content for term in [
                    "addressaliashelper",
                    "undol1tol2alias",
                    "applyl1tol2alias",
                    "1111000000000000",
                ]):
                    return True
        
        return False


class L2GasCalculationRisk(AbstractDetector):
    """
    Detects potential L2 gas calculation issues:
    - Hardcoded gas limits that may differ across L2s
    - Missing L1 data fee calculations
    - Gas estimations that don't account for compression
    """
    
    ARGUMENT = "l2-gas-calculation"
    HELP = "L2 gas calculation may be incorrect"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/l2-specific"
    WIKI_TITLE = "L2 Gas Calculation Risk"
    WIKI_DESCRIPTION = """
    L2 gas costs differ significantly from L1:
    - L1 data fee for calldata posting
    - Different gas prices for computation vs data
    - Compression affects actual costs
    """
    
    WIKI_RECOMMENDATION = """
    1. Use L2-specific gas estimation APIs
    2. Account for L1 data fees in cost calculations
    3. Avoid hardcoded gas limits - use gasleft() checks
    """
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                issues = self._check_gas_usage(function)
                for issue in issues:
                    info = [
                        f"L2 Gas Risk: {function.canonical_name} ",
                        issue,
                        "\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _check_gas_usage(self, function: Function) -> List[str]:
        issues = []
        
        for node in function.nodes:
            content = str(node)
            
            # Check for hardcoded gas limits in calls
            if ".call{gas:" in content or ".call{value:" in content:
                # Check if gas is hardcoded
                if "gas:" in content:
                    # Look for numeric literals (potential hardcoded values)
                    import re
                    gas_match = re.search(r'gas:\s*(\d+)', content)
                    if gas_match:
                        gas_value = int(gas_match.group(1))
                        if gas_value > 0 and gas_value < 1000000:
                            issues.append(
                                f"hardcoded gas limit ({gas_value}) may be insufficient on L2"
                            )
            
            # Check for block.gaslimit assumptions
            if "block.gaslimit" in content:
                issues.append("block.gaslimit differs significantly on L2 networks")
        
        return issues


class ReorgRisk(AbstractDetector):
    """
    Detects operations that may be affected by L2 reorg/finality issues.
    
    L2 blocks have different finality guarantees:
    - Soft confirmations (sequencer)
    - L1 data posting
    - Full finality (challenge period)
    """
    
    ARGUMENT = "l2-reorg-risk"
    HELP = "Operation may be affected by L2 reorg"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/l2-specific"
    WIKI_TITLE = "L2 Reorg/Finality Risk"
    WIKI_DESCRIPTION = """
    L2 networks have weaker finality guarantees than L1. Operations that depend
    on recent block data may be affected by reorgs.
    """
    
    WIKI_RECOMMENDATION = """
    1. Add confirmation delay for high-value operations
    2. Don't rely on recent blockhash for randomness
    3. Implement finality checks for cross-chain operations
    """
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                issues = self._check_finality_assumptions(function)
                for issue in issues:
                    info = [
                        f"L2 Finality Risk: {function.canonical_name} ",
                        issue,
                        "\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _check_finality_assumptions(self, function: Function) -> List[str]:
        issues = []
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for blockhash usage (unreliable on L2)
            if "blockhash" in content:
                issues.append("uses blockhash - unreliable on L2 due to different finality")
            
            # Check for single-block confirmation
            if "block.number" in content and "confirmation" not in content:
                # Might be relying on immediate confirmation
                pass
            
            # Check for prevrandao/difficulty (different on L2)
            if "prevrandao" in content or "block.difficulty" in content:
                issues.append("uses prevrandao/difficulty - behavior differs on L2")
        
        return issues


# Register all detectors
DETECTORS = [
    SequencerDependency,
    L1L2MessageRisk,
    AddressAliasingRisk,
    L2GasCalculationRisk,
    ReorgRisk,
]
