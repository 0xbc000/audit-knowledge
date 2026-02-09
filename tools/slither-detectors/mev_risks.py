"""
Slither Custom Detector: MEV Risk Patterns

Detects common MEV vulnerabilities in DeFi smart contracts:
- Missing slippage protection
- Excessive slippage tolerance
- Missing deadline checks
- Flash loan enablers
- Price oracle manipulation risks

Author: Smart Contract Auditor (ClawdEva)
Version: 1.0.0
Date: 2026-02-05
"""

from typing import List, Optional, Tuple
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function, Contract
from slither.core.cfg.node import Node
from slither.core.expressions import CallExpression, Identifier, Literal
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import HighLevelCall, InternalCall, Binary, Assignment
from slither.analyses.data_dependency.data_dependency import is_dependent


class MissingSlippageProtection(AbstractDetector):
    """
    Detects swap/exchange functions without slippage protection.
    
    Vulnerable patterns:
    - swap() with minAmountOut = 0
    - swapExactTokensForTokens with no minimum
    - exchange() without output validation
    """
    
    ARGUMENT = "mev-missing-slippage"
    HELP = "Missing slippage protection in swap functions"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/mev-risks"
    WIKI_TITLE = "Missing Slippage Protection"
    WIKI_DESCRIPTION = "Swap functions without minimum output amount are vulnerable to sandwich attacks"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
    // MEV bot can sandwich this transaction for profit
}
```"""
    WIKI_RECOMMENDATION = "Always specify a reasonable minAmountOut based on expected output"
    
    # Common DEX router function signatures that need slippage protection
    DEX_SWAP_FUNCTIONS = {
        "swap",
        "swapExactTokensForTokens",
        "swapExactTokensForETH",
        "swapExactETHForTokens",
        "swapTokensForExactTokens",
        "exchange",
        "exchange_underlying",
        "sell",
        "buy",
        "exactInputSingle",
        "exactInput",
        "exactOutputSingle",
        "exactOutput",
    }
    
    # Parameter names that indicate minimum output
    MIN_OUTPUT_PARAMS = {
        "minamountout",
        "amountoutmin",
        "minout",
        "minimumamount",
        "minreceived",
        "minreturn",
        "amountoutminimum",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.is_constructor or function.visibility in ["private", "internal"]:
                    continue
                    
                issues = self._check_function_slippage(function)
                if issues:
                    for node, description in issues:
                        info = [
                            f"MEV Risk: {function.canonical_name} ",
                            description,
                            "\n\t- ",
                            node,
                            "\n"
                        ]
                        results.append(self.generate_result(info))
        
        return results
    
    def _check_function_slippage(self, function: Function) -> List[Tuple[Node, str]]:
        issues = []
        
        # Check if function makes external calls to DEX routers
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, HighLevelCall):
                    func_name = ir.function_name if ir.function_name else ""
                    
                    if func_name.lower() in [f.lower() for f in self.DEX_SWAP_FUNCTIONS]:
                        # Check if min amount parameter exists and is > 0
                        has_slippage = self._has_slippage_protection(ir, function)
                        
                        if not has_slippage:
                            issues.append((
                                node,
                                f"calls {func_name} without slippage protection"
                            ))
        
        return issues
    
    def _has_slippage_protection(self, ir: HighLevelCall, function: Function) -> bool:
        """Check if the call has proper slippage protection"""
        
        # Check function parameters for min output
        for param in function.parameters:
            if param.name.lower().replace("_", "") in self.MIN_OUTPUT_PARAMS:
                return True
        
        # Check call arguments for non-zero min amount
        if ir.arguments:
            for i, arg in enumerate(ir.arguments):
                # If argument is a literal 0, no protection
                if hasattr(arg, 'value') and str(arg.value) == '0':
                    return False
                    
                # Check if the argument is user-controlled (good)
                if any(is_dependent(arg, param, function) for param in function.parameters):
                    return True
        
        return False


class ExcessiveSlippageTolerance(AbstractDetector):
    """
    Detects swap functions with excessive slippage tolerance (>5%).
    """
    
    ARGUMENT = "mev-excessive-slippage"
    HELP = "Excessive slippage tolerance in swap functions"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/mev-risks"
    WIKI_TITLE = "Excessive Slippage Tolerance"
    WIKI_DESCRIPTION = "Slippage tolerance >5% makes transactions profitable for MEV extraction"
    
    WIKI_RECOMMENDATION = "Use slippage tolerance of 0.5-2% for most trades"
    
    # Threshold: 5% slippage is considered excessive
    MAX_SLIPPAGE_BPS = 500  # 5% in basis points
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for var in contract.state_variables:
                if self._is_slippage_variable(var):
                    issues = self._check_slippage_value(var, contract)
                    for issue in issues:
                        results.append(self.generate_result(issue))
        
        return results
    
    def _is_slippage_variable(self, var: StateVariable) -> bool:
        name = var.name.lower()
        return any(term in name for term in [
            "slippage", "tolerance", "maxslip", "minout"
        ])
    
    def _check_slippage_value(self, var: StateVariable, contract: Contract) -> List:
        issues = []
        
        # Check initial value
        if var.expression:
            value = self._extract_numeric_value(var.expression)
            if value and value > self.MAX_SLIPPAGE_BPS:
                issues.append([
                    f"Excessive slippage tolerance: {var.canonical_name} = {value}bps (>{self.MAX_SLIPPAGE_BPS}bps)\n"
                ])
        
        return issues
    
    def _extract_numeric_value(self, expression) -> Optional[int]:
        if hasattr(expression, 'value'):
            try:
                return int(expression.value)
            except (ValueError, TypeError):
                return None
        return None


class MissingDeadlineCheck(AbstractDetector):
    """
    Detects swap/DEX interactions without deadline/expiry checks.
    Stale transactions can be executed at unfavorable prices.
    """
    
    ARGUMENT = "mev-missing-deadline"
    HELP = "Missing deadline check in swap functions"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/mev-risks"
    WIKI_TITLE = "Missing Deadline Check"
    WIKI_DESCRIPTION = """
    Swap transactions without deadline can be held by block builders and executed
    when market conditions are unfavorable for the user.
    """
    
    WIKI_RECOMMENDATION = "Always include a deadline parameter and check block.timestamp"
    
    DEADLINE_PARAMS = {"deadline", "expiry", "validuntil", "expires", "timeout"}
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_swap_function(function) and not self._has_deadline_check(function):
                    info = [
                        f"MEV Risk: {function.canonical_name} ",
                        "lacks deadline check - transactions can be delayed and front-run\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _is_swap_function(self, function: Function) -> bool:
        name = function.name.lower()
        return any(term in name for term in [
            "swap", "exchange", "trade", "sell", "buy"
        ])
    
    def _has_deadline_check(self, function: Function) -> bool:
        # Check parameters
        for param in function.parameters:
            if param.name.lower().replace("_", "") in self.DEADLINE_PARAMS:
                return True
        
        # Check for block.timestamp comparisons
        for node in function.nodes:
            if node.contains_require_or_assert():
                content = str(node.expression) if node.expression else ""
                if "block.timestamp" in content or "deadline" in content.lower():
                    return True
        
        return False


class FlashLoanEnabler(AbstractDetector):
    """
    Detects functions that may enable flash loan attacks:
    - Unrestricted external calls with user-controlled addresses
    - Callback mechanisms without proper validation
    - State changes after external calls (reentrancy vector)
    """
    
    ARGUMENT = "mev-flash-loan-enabler"
    HELP = "Function may enable flash loan attacks"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/mev-risks"
    WIKI_TITLE = "Flash Loan Attack Enabler"
    WIKI_DESCRIPTION = """
    Functions that allow external calls with state changes can be exploited
    in flash loan attacks for price manipulation or MEV extraction.
    """
    
    WIKI_RECOMMENDATION = "Use reentrancy guards, validate callback sources, and use commit-reveal patterns"
    
    # Known flash loan provider callback signatures
    FLASH_LOAN_CALLBACKS = {
        "onflashloan",
        "executeOperation", 
        "uniswapV2Call",
        "uniswapV3FlashCallback",
        "pancakeCall",
        "callee",
        "callback",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if function.visibility in ["external", "public"]:
                    issues = self._check_flash_loan_risk(function, contract)
                    for issue in issues:
                        results.append(self.generate_result(issue))
        
        return results
    
    def _check_flash_loan_risk(self, function: Function, contract: Contract) -> List:
        issues = []
        
        # Check for callback pattern without msg.sender validation
        if function.name.lower().replace("_", "") in self.FLASH_LOAN_CALLBACKS:
            if not self._validates_caller(function):
                issues.append([
                    f"Flash loan callback {function.canonical_name} ",
                    "does not validate caller - may enable unauthorized calls\n"
                ])
        
        # Check for external calls followed by state changes
        external_call_nodes = []
        state_change_nodes = []
        
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, HighLevelCall) and ir.destination != contract:
                    external_call_nodes.append(node)
                if isinstance(ir, Assignment) and isinstance(ir.lvalue, StateVariable):
                    state_change_nodes.append(node)
        
        # Check if state change happens after external call
        for ext_node in external_call_nodes:
            for state_node in state_change_nodes:
                if state_node.node_id > ext_node.node_id:
                    if not self._has_reentrancy_guard(function):
                        issues.append([
                            f"State change after external call in {function.canonical_name} ",
                            f"at {state_node} - potential flash loan/reentrancy vector\n"
                        ])
                        break
        
        return issues
    
    def _validates_caller(self, function: Function) -> bool:
        for node in function.nodes:
            if node.contains_require_or_assert():
                content = str(node.expression) if node.expression else ""
                if "msg.sender" in content:
                    return True
        return False
    
    def _has_reentrancy_guard(self, function: Function) -> bool:
        # Check for common reentrancy guard modifiers
        for modifier in function.modifiers:
            name = modifier.name.lower()
            if any(term in name for term in ["nonreentrant", "lock", "mutex"]):
                return True
        return False


class OracleManipulationRisk(AbstractDetector):
    """
    Detects potential oracle manipulation vulnerabilities:
    - Using spot prices instead of TWAP
    - Single-block price readings
    - Missing freshness checks on oracle data
    """
    
    ARGUMENT = "mev-oracle-manipulation"
    HELP = "Potential oracle manipulation vulnerability"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    
    WIKI = "https://github.com/smart-contract-auditor/detectors/mev-risks"
    WIKI_TITLE = "Oracle Manipulation Risk"
    WIKI_DESCRIPTION = """
    Using spot prices or stale oracle data enables flash loan attacks and
    sandwich attacks for profit extraction.
    """
    
    WIKI_RECOMMENDATION = "Use TWAP oracles, implement freshness checks, and add circuit breakers"
    
    # Spot price functions (vulnerable)
    SPOT_PRICE_FUNCTIONS = {
        "getspot",
        "getspotprice", 
        "getreserves",
        "slot0",  # Uniswap V3 spot price
        "getprice",
        "getrate",
    }
    
    # TWAP functions (safer)
    TWAP_FUNCTIONS = {
        "observe",
        "consult",
        "twap",
        "gettwap",
        "getaverageprice",
    }
    
    def _detect(self) -> List:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                issues = self._check_oracle_usage(function)
                for issue in issues:
                    results.append(self.generate_result(issue))
        
        return results
    
    def _check_oracle_usage(self, function: Function) -> List:
        issues = []
        uses_spot_price = False
        uses_twap = False
        has_freshness_check = False
        
        for node in function.nodes:
            content = str(node).lower()
            
            # Check for spot price usage
            for spot_func in self.SPOT_PRICE_FUNCTIONS:
                if spot_func in content:
                    uses_spot_price = True
            
            # Check for TWAP usage
            for twap_func in self.TWAP_FUNCTIONS:
                if twap_func in content:
                    uses_twap = True
            
            # Check for freshness validation
            if "updatedat" in content or "staleness" in content or "heartbeat" in content:
                has_freshness_check = True
            
            # Check for Chainlink roundId validation
            if "roundid" in content and node.contains_require_or_assert():
                has_freshness_check = True
        
        # Report issues
        if uses_spot_price and not uses_twap:
            issues.append([
                f"Oracle manipulation risk in {function.canonical_name}: ",
                "uses spot price without TWAP - vulnerable to flash loan manipulation\n"
            ])
        
        if (uses_spot_price or uses_twap) and not has_freshness_check:
            issues.append([
                f"Stale oracle risk in {function.canonical_name}: ",
                "no freshness/staleness check on oracle data\n"
            ])
        
        return issues


# Register all detectors
DETECTORS = [
    MissingSlippageProtection,
    ExcessiveSlippageTolerance,
    MissingDeadlineCheck,
    FlashLoanEnabler,
    OracleManipulationRisk,
]
