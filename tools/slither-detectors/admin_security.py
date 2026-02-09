"""
Slither Custom Detector: Admin Security (L2 Focus)

Detects admin-related vulnerabilities critical for L2 protocols:
- Admin takeover + bridge exit patterns
- Proxy upgrade without timelock
- Shared deployer risks
- Multi-sig bypass

Based on real cases:
- USDGambit/TLP $1.5M exploit (Jan 2026) - Shared deployer, admin takeover, bridge exit

Author: Smart Contract Auditor (ClawdEva)
Version: 1.0.0
Date: 2026-02-06
"""

from typing import List, Optional
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function, Contract
from slither.core.cfg.node import Node
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import HighLevelCall, InternalCall


class ProxyUpgradeNoTimelock(AbstractDetector):
    """
    Detects proxy upgrade functions without timelock protection.
    
    On L2s, attackers who gain admin access can:
    1. Deploy malicious implementation
    2. Upgrade proxy
    3. Drain funds
    4. Bridge to L1 and escape before detection
    
    Timelock must be > L2→L1 bridge delay (7 days for Arbitrum/Optimism)
    """
    
    ARGUMENT = "admin-upgrade-no-timelock"
    HELP = "Proxy upgrade without timelock - instant admin takeover risk"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/admin-security"
    WIKI_TITLE = "Proxy Upgrade Without Timelock"
    WIKI_DESCRIPTION = """
    Proxy contracts that allow immediate upgrades are vulnerable to admin key compromise.
    On L2 networks, this is especially dangerous because attackers can drain funds and
    exit via the L2→L1 bridge before anyone notices.
    
    Real case: USDGambit/TLP ($1.5M, Jan 2026) - Admin key compromised, immediate upgrade,
    funds drained and bridged to L1, laundered via Tornado Cash.
    """
    
    WIKI_RECOMMENDATION = """
    1. Implement timelock > 7 days (longer than L2→L1 bridge delay)
    2. Use multi-sig for admin operations
    3. Set up L1 monitoring for upgrade proposals
    4. Consider L1-based governance for critical upgrades
    """
    
    # Upgrade-related function patterns
    UPGRADE_PATTERNS = {
        "upgrade",
        "upgradeto",
        "upgradetoandcall",
        "setimplementation",
        "changeimplementation",
        "_setimplementation",
    }
    
    # Timelock-related patterns
    TIMELOCK_PATTERNS = {
        "timelock",
        "delay",
        "scheduledupgrade",
        "pendingimplementation",
        "upgradequeue",
        "mindelay",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            # Check if this is a proxy or admin contract
            if not self._is_proxy_or_admin(contract):
                continue
            
            has_timelock = self._contract_has_timelock(contract)
            
            for function in contract.functions:
                if self._is_upgrade_function(function):
                    if not has_timelock and not self._function_has_delay(function):
                        info = [
                            f"🚨 Admin Risk: {function.canonical_name} ",
                            "allows immediate proxy upgrade without timelock\n",
                            "On L2: Attacker can upgrade → drain → bridge to L1 in one tx\n",
                            "Recommendation: Add timelock > 7 days (L2→L1 bridge delay)\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_proxy_or_admin(self, contract: Contract) -> bool:
        name = contract.name.lower()
        return any(term in name for term in [
            "proxy", "admin", "upgradeable", "upgradeability",
            "proxyadmin", "transparentproxy", "uups"
        ])
    
    def _is_upgrade_function(self, function: Function) -> bool:
        name = function.name.lower().replace("_", "")
        return any(pattern in name for pattern in self.UPGRADE_PATTERNS)
    
    def _contract_has_timelock(self, contract: Contract) -> bool:
        # Check state variables for timelock-related vars
        for var in contract.state_variables:
            name = var.name.lower()
            if any(pattern in name for pattern in self.TIMELOCK_PATTERNS):
                return True
        
        # Check function names for timelock pattern
        for function in contract.functions:
            name = function.name.lower()
            if any(pattern in name for pattern in ["schedule", "queue", "execute"]):
                return True
        
        return False
    
    def _function_has_delay(self, function: Function) -> bool:
        for node in function.nodes:
            content = str(node).lower()
            if any(pattern in content for pattern in self.TIMELOCK_PATTERNS):
                return True
            # Check for timestamp comparison (delay enforcement)
            if "block.timestamp" in content and ">=" in content:
                return True
        return False


class SharedDeployerRisk(AbstractDetector):
    """
    Detects patterns indicating shared deployer key risks.
    
    Multiple protocols sharing the same deployer create single point of failure:
    - Compromise of deployer key affects all protocols
    - Often deployer retains admin privileges
    
    Real case: USDGambit + TLP shared deployer → both exploited simultaneously
    """
    
    ARGUMENT = "admin-shared-deployer"
    HELP = "Contract may be using deployer as admin - single point of failure"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/admin-security"
    WIKI_TITLE = "Shared Deployer Risk"
    WIKI_DESCRIPTION = """
    When contracts use the deployer address as admin without proper transition
    to a dedicated admin/multi-sig, they share a single point of failure with
    any other contracts deployed by the same address.
    """
    
    WIKI_RECOMMENDATION = """
    1. Transfer admin to dedicated multi-sig immediately after deployment
    2. Never share deployer keys across protocols
    3. Use hardware wallets for deployment keys
    4. Implement 2-of-N multi-sig for all admin functions
    """
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            issues = self._check_deployer_patterns(contract)
            for issue in issues:
                info = [
                    f"🔑 Admin Risk: {contract.name} ",
                    issue,
                    "\n"
                ]
                results.append(self.generate_result(info))
        
        return results
    
    def _check_deployer_patterns(self, contract: Contract) -> List[str]:
        issues = []
        
        # Check constructor for admin assignment patterns
        constructor = contract.constructor
        if constructor:
            for node in constructor.nodes:
                content = str(node).lower()
                
                # admin = msg.sender (deployer becomes admin)
                if "msg.sender" in content and "admin" in content:
                    # Check if there's a transfer mechanism
                    has_transfer = self._has_admin_transfer(contract)
                    if not has_transfer:
                        issues.append(
                            "assigns deployer (msg.sender) as admin without transfer mechanism"
                        )
                
                # owner = msg.sender
                if "msg.sender" in content and "owner" in content:
                    has_transfer = self._has_ownership_transfer(contract)
                    if not has_transfer:
                        issues.append(
                            "assigns deployer as owner - ensure ownership is transferred to multi-sig"
                        )
        
        return issues
    
    def _has_admin_transfer(self, contract: Contract) -> bool:
        for function in contract.functions:
            name = function.name.lower()
            if any(term in name for term in ["transferadmin", "setadmin", "changeadmin"]):
                return True
        return False
    
    def _has_ownership_transfer(self, contract: Contract) -> bool:
        for function in contract.functions:
            name = function.name.lower()
            if any(term in name for term in ["transferownership", "setowner", "changeowner"]):
                return True
        return False


class L2BridgeExitRisk(AbstractDetector):
    """
    Detects patterns that could enable bridge exit attacks on L2.
    
    Attack pattern:
    1. Gain admin access
    2. Drain protocol funds
    3. Bridge to L1 mainnet
    4. Funds become nearly untraceable (7-day delay provides escape window)
    
    Detection focuses on:
    - Admin can initiate large withdrawals
    - No withdrawal limits or delays
    - Direct access to bridge functions
    """
    
    ARGUMENT = "l2-bridge-exit-risk"
    HELP = "Admin may drain funds via L2→L1 bridge"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/admin-security"
    WIKI_TITLE = "L2 Bridge Exit Attack Risk"
    WIKI_DESCRIPTION = """
    On L2 networks, compromised admins can drain funds and escape via the L2→L1 bridge.
    The 7-day challenge period (Optimistic Rollups) provides ample time to:
    - Launder through mixers
    - Convert to other assets
    - Move to other chains
    
    This detector identifies admin-accessible withdrawal patterns without proper limits.
    """
    
    WIKI_RECOMMENDATION = """
    1. Implement withdrawal limits per time period
    2. Add multi-sig requirements for large withdrawals
    3. Set up monitoring alerts for unusual admin activity
    4. Consider L1-based approval for large fund movements
    """
    
    # Bridge-related patterns
    BRIDGE_PATTERNS = {
        "bridge",
        "withdraw",
        "l1gateway",
        "outboundtransfer",
        "sendtoL1",
        "initiatewithdrawal",
    }
    
    # Admin-restricted patterns
    ADMIN_PATTERNS = {
        "onlyadmin",
        "onlyowner",
        "onlygovernance",
        "onlyauthorized",
        "adminonly",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_admin_withdrawal(function):
                    issues = self._check_withdrawal_safety(function)
                    for issue in issues:
                        info = [
                            f"🌉 L2 Exit Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_admin_withdrawal(self, function: Function) -> bool:
        name = function.name.lower()
        
        # Check if function can move funds
        is_withdrawal = any(term in name for term in [
            "withdraw", "rescue", "recover", "sweep", "transfer", "bridge"
        ])
        
        if not is_withdrawal:
            return False
        
        # Check if admin-restricted
        for modifier in function.modifiers:
            if any(pattern in modifier.name.lower() for pattern in self.ADMIN_PATTERNS):
                return True
        
        return False
    
    def _check_withdrawal_safety(self, function: Function) -> List[str]:
        issues = []
        has_limit = False
        has_delay = False
        has_multisig = False
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for withdrawal limits
            if any(term in content for term in ["maxwithdrawal", "withdrawallimit", "dailylimit"]):
                has_limit = True
            
            # Check for delay mechanism
            if any(term in content for term in ["delay", "timelock", "pending"]):
                has_delay = True
            
            # Check for multi-sig
            if any(term in content for term in ["multisig", "threshold", "signatures"]):
                has_multisig = True
        
        if not has_limit:
            issues.append("no withdrawal limit - admin can drain all funds")
        
        if not has_delay:
            issues.append("no withdrawal delay - instant drain possible")
        
        if not has_multisig:
            issues.append("no multi-sig requirement - single key compromise sufficient")
        
        return issues


class EmergencyWithdrawRisk(AbstractDetector):
    """
    Detects risky emergency withdraw patterns:
    - emergencyWithdraw without user consent
    - Rescue functions that can target user funds
    - Admin can force liquidation
    """
    
    ARGUMENT = "admin-emergency-withdraw"
    HELP = "Emergency withdraw may enable admin to steal user funds"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/admin-security"
    WIKI_TITLE = "Emergency Withdraw Risk"
    WIKI_DESCRIPTION = """
    Emergency withdraw functions are often necessary for protocol safety, but
    poorly designed ones can allow admins to steal user funds.
    
    Red flags:
    - Admin can withdraw user funds without user action
    - No limits on rescued amounts
    - Rescue can target any token/pool
    """
    
    WIKI_RECOMMENDATION = """
    1. Emergency withdraw should only move user's own funds
    2. Require user signature for forced withdrawals
    3. Limit rescue to stuck/excess tokens only
    4. Add time delay for large emergency actions
    """
    
    EMERGENCY_PATTERNS = {
        "emergency",
        "rescue",
        "recover",
        "sweep",
        "panic",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_emergency_function(function):
                    issues = self._check_emergency_safety(function)
                    for issue in issues:
                        info = [
                            f"⚠️ Emergency Risk: {function.canonical_name} ",
                            issue,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _is_emergency_function(self, function: Function) -> bool:
        name = function.name.lower()
        return any(pattern in name for pattern in self.EMERGENCY_PATTERNS)
    
    def _check_emergency_safety(self, function: Function) -> List[str]:
        issues = []
        restricted_to_admin = False
        requires_user_action = False
        has_token_whitelist = False
        
        # Check modifiers for admin restriction
        for modifier in function.modifiers:
            if any(term in modifier.name.lower() for term in ["admin", "owner", "governance"]):
                restricted_to_admin = True
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check if user action is required
            if "msg.sender" in content:
                # Check if comparing to user/owner of position
                if any(term in content for term in ["user", "depositor", "position"]):
                    requires_user_action = True
            
            # Check for token whitelist
            if "allowedtoken" in content or "rescuetokens" in content:
                has_token_whitelist = True
        
        if restricted_to_admin and not requires_user_action:
            issues.append("admin can withdraw without user consent")
        
        if not has_token_whitelist:
            issues.append("no token whitelist - can rescue any token including user deposits")
        
        return issues


class MultiSigBypassRisk(AbstractDetector):
    """
    Detects patterns that could bypass multi-sig protection:
    - Single signer can execute with threshold=1
    - Threshold can be reduced by existing signers
    - Signer management has no delay
    """
    
    ARGUMENT = "admin-multisig-bypass"
    HELP = "Multi-sig protection may be bypassable"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/admin-security"
    WIKI_TITLE = "Multi-Sig Bypass Risk"
    WIKI_DESCRIPTION = """
    Multi-sig wallets provide protection only if properly configured.
    Common bypass vectors:
    - Threshold of 1 (single signer)
    - Threshold can be lowered without delay
    - Signers can be replaced without delay
    """
    
    WIKI_RECOMMENDATION = """
    1. Minimum threshold of 2 (preferably higher for large TVL)
    2. Timelock on threshold changes (7+ days)
    3. Timelock on signer additions/removals
    4. Monitor all multi-sig configuration changes
    """
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            if self._is_multisig_contract(contract):
                issues = self._check_multisig_safety(contract)
                for issue in issues:
                    info = [
                        f"🔐 Multi-Sig Risk: {contract.name} ",
                        issue,
                        "\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _is_multisig_contract(self, contract: Contract) -> bool:
        name = contract.name.lower()
        return any(term in name for term in [
            "multisig", "gnosis", "safe", "wallet", "signers"
        ])
    
    def _check_multisig_safety(self, contract: Contract) -> List[str]:
        issues = []
        threshold_has_delay = False
        signer_change_has_delay = False
        
        for function in contract.functions:
            name = function.name.lower()
            
            # Check threshold change function
            if "threshold" in name:
                if self._function_has_delay(function):
                    threshold_has_delay = True
                else:
                    issues.append("threshold change has no timelock")
            
            # Check signer management
            if any(term in name for term in ["addsigner", "removesigner", "addowner", "removeowner"]):
                if self._function_has_delay(function):
                    signer_change_has_delay = True
                else:
                    issues.append("signer management has no timelock")
        
        return issues
    
    def _function_has_delay(self, function: Function) -> bool:
        for node in function.nodes:
            content = str(node).lower()
            if any(term in content for term in ["delay", "timelock", "pending", "queue"]):
                return True
        return False


# Register all detectors
DETECTORS = [
    ProxyUpgradeNoTimelock,
    SharedDeployerRisk,
    L2BridgeExitRisk,
    EmergencyWithdrawRisk,
    MultiSigBypassRisk,
]
