"""
FCFS and Tiering System Vulnerability Detectors for Slither

Based on real vulnerabilities from:
- LayerEdge (Sherlock, 2026): FCFS tier boundary bugs, Fenwick tree issues

Detects:
1. Integer division tier boundary edge cases (e.g., 10N+4 pattern)
2. Fenwick tree inconsistency (ghost stakers)
3. Cascading tier update gas DoS
4. Position gaming vulnerabilities
5. Ranking data structure misalignment

Author: Smart Contract Auditor (ClawdEva)
Date: 2026-02-07
"""

from typing import List, Set
from slither.core.declarations import Function, Contract
from slither.core.cfg.node import Node
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output


class TierBoundaryEdgeCaseDetector(AbstractDetector):
    """
    Detects integer division edge cases in tier boundary calculations.
    
    From LayerEdge H-2, H-7:
    - Tier boundaries calculated as `stakerCount * tierPercent / 100`
    - At specific counts (e.g., 10N+4 for 40%/30%/30% split), 
      boundaries collide causing wrong tier assignments
    
    Example: 14 stakers with 40%/30%/30% tiers
    - Tier 1: 14 * 40 / 100 = 5
    - Tier 2: 14 * 70 / 100 = 9  (cumulative)
    - Boundary between T1/T2 should be at 5, T2/T3 at 9
    - But 14 * 30 / 100 = 4, so tier 2 only has 4 slots, not 5
    """
    
    ARGUMENT = "fcfs-tier-boundary"
    HELP = "Integer division in tier boundaries may cause edge case bugs"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#fcfs-tier-boundary"
    WIKI_TITLE = "FCFS Tier Boundary Edge Case"
    WIKI_DESCRIPTION = "Integer division in tier calculations can cause boundary collisions at specific staker counts"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function getTier(uint256 rank, uint256 total) returns (uint8) {
    uint256 tier1Boundary = total * 40 / 100;  // Integer division!
    uint256 tier2Boundary = total * 70 / 100;
    
    if (rank <= tier1Boundary) return 1;
    if (rank <= tier2Boundary) return 2;
    return 3;
}
```
At total=14:
- tier1Boundary = 5
- tier2Boundary = 9
- But staker at rank 6 gets tier 2, even though 14*40/100 = 5.6 (should be tier 1)
"""
    WIKI_RECOMMENDATION = """
1. Use cumulative percentage calculation with proper rounding
2. Test all modular edge cases (totalCount % 100)
3. Consider fixed-point math for boundary calculations
4. Add explicit tests for N*10+4, N*10+5, etc. edge cases
"""
    
    # Patterns indicating tier/rank calculations
    TIER_PATTERNS = ["tier", "rank", "level", "boundary", "threshold"]
    DIVISION_PATTERNS = ["/ 100", "* 100 /", "percent", "%"]
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if not self._handles_tiers(function):
                    continue
                
                # Check for potential integer division issues
                if self._has_tier_division(function):
                    info = [
                        function,
                        " calculates tier boundaries using integer division\n",
                        "At specific staker counts (e.g., 10N+4), boundaries may collide\n"
                    ]
                    
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _handles_tiers(self, function: Function) -> bool:
        """Check if function handles tier calculations"""
        func_name = function.name.lower()
        if any(pattern in func_name for pattern in self.TIER_PATTERNS):
            return True
        
        for node in function.nodes:
            node_str = str(node).lower()
            if any(pattern in node_str for pattern in self.TIER_PATTERNS):
                return True
        
        return False
    
    def _has_tier_division(self, function: Function) -> bool:
        """Check for integer division in tier calculations"""
        for node in function.nodes:
            node_str = str(node).lower()
            # Check for division by 100 or percentage calculations
            if "/ 100" in node_str or "/ 1000" in node_str:
                if any(pattern in node_str for pattern in self.TIER_PATTERNS):
                    return True
            # Check for percentage patterns
            if "percent" in node_str or "bps" in node_str:
                return True
        
        return False


class GhostStakerDetector(AbstractDetector):
    """
    Detects potential ghost staker issues in ranking data structures.
    
    From LayerEdge H-3:
    - Fenwick tree tracked stakers, but minStakeAmount could be 0
    - Users could "stake" 0 amount, getting ranked without real stake
    - Ghost stakers occupy ranking positions, displacing real stakers
    """
    
    ARGUMENT = "fcfs-ghost-staker"
    HELP = "Zero-amount staking may create ghost entries in ranking"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#fcfs-ghost-staker"
    WIKI_TITLE = "Ghost Staker Vulnerability"
    WIKI_DESCRIPTION = "Zero or minimum stake may create ranking entries without real economic stake"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public stakedAmount;
FenwickTree public rankingTree;

function stake(uint256 amount) external {
    // Missing: require(amount >= minStakeAmount)
    stakedAmount[msg.sender] += amount;
    rankingTree.add(msg.sender);  // Added to ranking even with 0 stake!
}
```
Attacker stakes 0, gets ranked, displaces real stakers from higher tiers.
"""
    WIKI_RECOMMENDATION = """
1. Enforce minimum stake amount > 0
2. Only add to ranking data structure when stake is meaningful
3. Remove from ranking when stake falls below minimum
4. Verify ranking data structure matches actual stake state
"""
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                func_name = function.name.lower()
                
                # Check stake/deposit functions
                if not any(p in func_name for p in ["stake", "deposit", "join", "register"]):
                    continue
                
                # Check for minimum amount enforcement
                if not self._enforces_minimum(function):
                    info = [
                        function,
                        " may allow zero-amount staking, creating ghost entries\n"
                    ]
                    
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _enforces_minimum(self, function: Function) -> bool:
        """Check if function enforces minimum stake amount"""
        for node in function.nodes:
            node_str = str(node).lower()
            # Check for minimum amount requirements
            if "require" in node_str or "revert" in node_str:
                if any(p in node_str for p in ["amount > 0", "amount >= min", "minstake", "_amount > 0"]):
                    return True
            # Check for explicit > 0 checks
            if "if" in node_str and "== 0" in node_str and "revert" in node_str:
                return True
        
        return False


class CascadingTierUpdateDoSDetector(AbstractDetector):
    """
    Detects O(k × log n) gas exhaustion in cascading tier updates.
    
    From LayerEdge H-1:
    - Each stake change triggers tier recalculation
    - Tier changes cascade through the system
    - With 1000+ stakers, single operation can exceed block gas limit
    """
    
    ARGUMENT = "fcfs-cascade-dos"
    HELP = "Cascading tier updates may cause gas exhaustion DoS"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#fcfs-cascade-dos"
    WIKI_TITLE = "Cascading Tier Update DoS"
    WIKI_DESCRIPTION = "Tier update operations with O(k × log n) complexity may exhaust gas"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function updateStake(uint256 newAmount) external {
    updateRanking(msg.sender);  // O(log n)
    
    // Cascade: update all affected tiers
    for (uint i = 0; i < affectedUsers.length; i++) {  // O(k) users
        recalculateTier(affectedUsers[i]);  // O(log n) each
    }
}
```
With 1000 users, O(1000 × 10) = 10,000 operations per stake change.
At 100 gas each = 1M gas per operation, risking block limit.
"""
    WIKI_RECOMMENDATION = """
1. Use lazy tier calculation (calculate on read, not write)
2. Batch tier updates in separate transactions
3. Cap maximum affected users per transaction
4. Use epoch-based tier snapshots instead of live updates
"""
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                # Check functions that modify rankings
                if not self._modifies_ranking(function):
                    continue
                
                # Check for loops that might cascade
                if self._has_cascading_loop(function):
                    info = [
                        function,
                        " may trigger cascading tier updates with O(k × log n) gas cost\n",
                        "Consider lazy calculation or batched updates\n"
                    ]
                    
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _modifies_ranking(self, function: Function) -> bool:
        """Check if function modifies ranking/tier state"""
        func_name = function.name.lower()
        modifying_patterns = ["stake", "unstake", "update", "rerank", "recalculate"]
        
        if any(p in func_name for p in modifying_patterns):
            return True
        
        # Check for ranking state modifications
        for var in function.state_variables_written:
            var_name = var.name.lower()
            if any(p in var_name for p in ["rank", "tier", "position", "tree", "fenwick"]):
                return True
        
        return False
    
    def _has_cascading_loop(self, function: Function) -> bool:
        """Check for loops that might trigger cascading updates"""
        loop_count = 0
        has_update_in_loop = False
        
        for node in function.nodes:
            # Count loop constructs
            if node.type.name in ["STARTLOOP", "IFLOOP"]:
                loop_count += 1
            
            # Check for ranking updates in loops
            node_str = str(node).lower()
            if loop_count > 0:
                if any(p in node_str for p in ["update", "recalculate", "tier", "rank"]):
                    has_update_in_loop = True
        
        return has_update_in_loop


class PositionGamingDetector(AbstractDetector):
    """
    Detects position gaming vulnerabilities in FCFS systems.
    
    Attackers may:
    - Stake/unstake to manipulate their rank
    - Frontrun other stakers to get better position
    - Use multiple wallets to control tier distribution
    """
    
    ARGUMENT = "fcfs-position-gaming"
    HELP = "FCFS ranking may be vulnerable to position gaming"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#fcfs-position-gaming"
    WIKI_TITLE = "FCFS Position Gaming"
    WIKI_DESCRIPTION = "Ranking system may be manipulated through strategic staking/unstaking"
    WIKI_RECOMMENDATION = """
1. Add cooldown periods for stake/unstake
2. Use commit-reveal for stake amounts
3. Implement time-weighted staking
4. Add anti-sybil measures (e.g., proof of humanity)
"""
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            # Check if contract has FCFS/ranking mechanics
            if not self._has_fcfs_mechanics(contract):
                continue
            
            # Check for anti-gaming measures
            if not self._has_anti_gaming(contract):
                info = [
                    contract,
                    " implements FCFS ranking without anti-gaming measures\n",
                    "Consider cooldowns, time-weighting, or commit-reveal\n"
                ]
                
                res = self.generate_result(info)
                results.append(res)
        
        return results
    
    def _has_fcfs_mechanics(self, contract: Contract) -> bool:
        """Check if contract implements FCFS/ranking"""
        for var in contract.state_variables:
            var_name = var.name.lower()
            if any(p in var_name for p in ["rank", "tier", "position", "fcfs", "queue"]):
                return True
        
        for func in contract.functions:
            if any(p in func.name.lower() for p in ["rank", "tier", "position"]):
                return True
        
        return False
    
    def _has_anti_gaming(self, contract: Contract) -> bool:
        """Check for anti-gaming measures"""
        for var in contract.state_variables:
            var_name = var.name.lower()
            if any(p in var_name for p in ["cooldown", "lockup", "timelock", "commit", "reveal"]):
                return True
        
        for func in contract.functions:
            func_name = func.name.lower()
            if any(p in func_name for p in ["cooldown", "commit", "reveal", "lock"]):
                return True
        
        return False


class FenwickTreeConsistencyDetector(AbstractDetector):
    """
    Detects potential Fenwick tree (Binary Indexed Tree) consistency issues.
    
    From LayerEdge H-3:
    - Fenwick tree state must match actual staking state
    - Insert/remove operations must be atomic with stake changes
    - Tree size must match actual staker count
    """
    
    ARGUMENT = "fcfs-fenwick-consistency"
    HELP = "Fenwick tree may become inconsistent with actual state"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#fcfs-fenwick-consistency"
    WIKI_TITLE = "Fenwick Tree Consistency"
    WIKI_DESCRIPTION = "Binary indexed tree operations may become inconsistent with actual state"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function stake(uint256 amount) external {
    stakedAmount[msg.sender] += amount;
    if (stakedAmount[msg.sender] > 0) {
        fenwickTree.insert(msg.sender);  // May be called multiple times!
    }
}

function unstake() external {
    uint256 amount = stakedAmount[msg.sender];
    stakedAmount[msg.sender] = 0;
    // Missing: fenwickTree.remove(msg.sender);
    payable(msg.sender).transfer(amount);
}
```
Tree contains stakers who have unstaked (ghost entries).
"""
    WIKI_RECOMMENDATION = """
1. Ensure tree insert/remove is atomic with stake state change
2. Use mapping to track if address is in tree
3. Add invariant checks: tree.size() == activeStakerCount
4. Consider using tree position as source of truth
"""
    
    TREE_PATTERNS = ["fenwick", "bit", "binaryindexed", "segmenttree", "rankingtree"]
    
    def _detect(self) -> List[Output]:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            if not self._uses_tree_structure(contract):
                continue
            
            # Check insert/remove consistency
            issues = self._check_consistency(contract)
            for issue, location in issues:
                info = [location, f" {issue}\n"]
                res = self.generate_result(info)
                results.append(res)
        
        return results
    
    def _uses_tree_structure(self, contract: Contract) -> bool:
        """Check if contract uses a tree-based ranking structure"""
        for var in contract.state_variables:
            if any(p in var.name.lower() for p in self.TREE_PATTERNS):
                return True
            if any(p in str(var.type).lower() for p in self.TREE_PATTERNS):
                return True
        
        return False
    
    def _check_consistency(self, contract: Contract) -> List[tuple]:
        """Check for tree consistency issues"""
        issues = []
        
        stake_funcs = []
        unstake_funcs = []
        
        for func in contract.functions:
            func_name = func.name.lower()
            if any(p in func_name for p in ["stake", "deposit", "join"]) and "unstake" not in func_name:
                stake_funcs.append(func)
            if any(p in func_name for p in ["unstake", "withdraw", "leave", "exit"]):
                unstake_funcs.append(func)
        
        # Check unstake functions for tree removal
        for func in unstake_funcs:
            has_tree_remove = False
            for node in func.nodes:
                node_str = str(node).lower()
                if any(p in node_str for p in ["remove", "delete", "pop"]):
                    has_tree_remove = True
            
            if not has_tree_remove:
                issues.append(("Unstake function may not remove from ranking tree", func))
        
        return issues


# =============================================================================
# DETECTOR REGISTRATION
# =============================================================================

DETECTORS = [
    TierBoundaryEdgeCaseDetector,
    GhostStakerDetector,
    CascadingTierUpdateDoSDetector,
    PositionGamingDetector,
    FenwickTreeConsistencyDetector,
]
