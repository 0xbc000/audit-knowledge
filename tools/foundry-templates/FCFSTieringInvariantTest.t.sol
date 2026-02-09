// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title FCFSTieringInvariantTest
 * @author Smart Contract Auditor (ClawdEva)
 * @notice Invariant test template for FCFS and tiering systems
 * @dev Based on LayerEdge vulnerabilities (Sherlock 2026)
 * 
 * Key vulnerabilities addressed:
 * - Tier boundary edge cases (H-2, H-7)
 * - Ghost stakers in ranking tree (H-3)
 * - Cascading tier update DoS (H-1)
 * - Position gaming vulnerabilities
 * - Fenwick tree consistency
 */

// =============================================================================
// INTERFACES - Replace with your protocol's interfaces
// =============================================================================

interface IStakingTiers {
    function stake(uint256 amount) external;
    function unstake(uint256 amount) external;
    function getStakedAmount(address account) external view returns (uint256);
    function getRank(address account) external view returns (uint256);
    function getTier(address account) external view returns (uint8);
    function getTierBoundary(uint8 tier) external view returns (uint256);
    function totalStakers() external view returns (uint256);
    function minStakeAmount() external view returns (uint256);
    function tierPercentages() external view returns (uint256[] memory);
}

interface IRankingTree {
    function size() external view returns (uint256);
    function getPosition(address account) external view returns (uint256);
    function contains(address account) external view returns (bool);
}

// =============================================================================
// INVARIANT TEST CONTRACT
// =============================================================================

contract FCFSTieringInvariantTest is Test {
    // Protocol contracts (replace with your implementations)
    IStakingTiers public staking;
    IRankingTree public rankingTree;
    
    // Test state tracking
    address[] public allStakers;
    mapping(address => bool) public isActiveStaker;
    uint256 public totalTrackedStake;
    
    // Tier configuration (example: 40% / 30% / 30%)
    uint256 constant TIER1_PERCENT = 40;
    uint256 constant TIER2_PERCENT = 30;
    uint256 constant TIER3_PERCENT = 30;
    
    // Test actors
    address[] public actors;
    
    // =============================================================================
    // SETUP
    // =============================================================================
    
    function setUp() public {
        // Deploy or fork your protocol contracts here
        // staking = IStakingTiers(deployStaking());
        // rankingTree = IRankingTree(address(staking));
        
        // Create test actors
        for (uint256 i = 0; i < 20; i++) {
            actors.push(makeAddr(string(abi.encodePacked("actor", i))));
            vm.deal(actors[i], 100 ether);
        }
        
        // Target contracts for fuzzing
        // targetContract(address(staking));
    }
    
    // =============================================================================
    // TIER BOUNDARY INVARIANTS
    // =============================================================================
    
    /**
     * @notice Tier boundaries must be consistent with staker count
     * @dev From LayerEdge H-2: At 10N+4 stakers, boundaries may collide
     */
    function invariant_tierBoundariesConsistent() public view {
        uint256 total = staking.totalStakers();
        if (total == 0) return;
        
        uint256 tier1Boundary = staking.getTierBoundary(1);
        uint256 tier2Boundary = staking.getTierBoundary(2);
        
        // Boundaries must be strictly increasing
        assertTrue(tier1Boundary < tier2Boundary, "Tier boundaries not strictly increasing");
        assertTrue(tier2Boundary <= total, "Tier 2 boundary exceeds total stakers");
        
        // Tier 1 should be approximately 40% of total
        uint256 expectedTier1 = (total * TIER1_PERCENT) / 100;
        uint256 tier1Count = tier1Boundary;
        
        // Allow ±1 for rounding, but should be close
        assertTrue(
            tier1Count >= expectedTier1 - 1 && tier1Count <= expectedTier1 + 1,
            "Tier 1 boundary deviates significantly from expected"
        );
    }
    
    /**
     * @notice Test specific edge cases: 10N+4 pattern
     * @dev From LayerEdge H-2: 14, 24, 34... stakers cause boundary issues
     */
    function invariant_edgeCaseStakerCounts() public view {
        uint256 total = staking.totalStakers();
        
        // Check if we're at a dangerous edge case
        if (total % 10 == 4 && total >= 14) {
            // At these counts, ensure tiers are still valid
            for (uint256 i = 0; i < allStakers.length && i < 20; i++) {
                address staker = allStakers[i];
                if (!isActiveStaker[staker]) continue;
                
                uint8 tier = staking.getTier(staker);
                uint256 rank = staking.getRank(staker);
                
                // Verify tier matches rank
                uint256 tier1Bound = staking.getTierBoundary(1);
                uint256 tier2Bound = staking.getTierBoundary(2);
                
                if (rank <= tier1Bound) {
                    assertEq(tier, 1, "Rank in tier 1 range but wrong tier assigned");
                } else if (rank <= tier2Bound) {
                    assertEq(tier, 2, "Rank in tier 2 range but wrong tier assigned");
                } else {
                    assertEq(tier, 3, "Rank in tier 3 range but wrong tier assigned");
                }
            }
        }
    }
    
    /**
     * @notice Tier sum must equal total stakers
     */
    function invariant_tierSumMatchesTotal() public view {
        uint256 total = staking.totalStakers();
        if (total == 0) return;
        
        uint256 tier1Count = staking.getTierBoundary(1);
        uint256 tier2Count = staking.getTierBoundary(2) - tier1Count;
        uint256 tier3Count = total - staking.getTierBoundary(2);
        
        assertEq(
            tier1Count + tier2Count + tier3Count,
            total,
            "Tier counts don't sum to total stakers"
        );
    }
    
    // =============================================================================
    // GHOST STAKER INVARIANTS
    // =============================================================================
    
    /**
     * @notice All ranked stakers must have non-zero stake
     * @dev From LayerEdge H-3: Ghost stakers occupy ranking without real stake
     */
    function invariant_noGhostStakers() public view {
        uint256 minStake = staking.minStakeAmount();
        
        for (uint256 i = 0; i < allStakers.length && i < 50; i++) {
            address staker = allStakers[i];
            
            uint256 stake = staking.getStakedAmount(staker);
            uint256 rank = staking.getRank(staker);
            
            // If has rank, must have minimum stake
            if (rank > 0) {
                assertTrue(
                    stake >= minStake,
                    "Ghost staker: has rank but insufficient stake"
                );
            }
            
            // If has stake >= minimum, should have rank
            if (stake >= minStake) {
                assertTrue(
                    rank > 0,
                    "Staker with valid stake has no rank"
                );
            }
        }
    }
    
    /**
     * @notice Minimum stake must be enforced
     */
    function invariant_minStakeEnforced() public view {
        uint256 minStake = staking.minStakeAmount();
        assertTrue(minStake > 0, "Minimum stake is zero - ghost stakers possible");
    }
    
    // =============================================================================
    // RANKING TREE CONSISTENCY INVARIANTS
    // =============================================================================
    
    /**
     * @notice Ranking tree size must match active staker count
     * @dev Ensures no stale entries in tree
     */
    function invariant_rankingTreeSizeMatchesStakers() public view {
        uint256 treeSize = rankingTree.size();
        uint256 stakerCount = staking.totalStakers();
        
        assertEq(treeSize, stakerCount, "Ranking tree size != total stakers");
    }
    
    /**
     * @notice Each active staker must be in ranking tree exactly once
     */
    function invariant_stakersInTreeExactlyOnce() public view {
        for (uint256 i = 0; i < allStakers.length && i < 50; i++) {
            address staker = allStakers[i];
            uint256 stake = staking.getStakedAmount(staker);
            
            if (stake >= staking.minStakeAmount()) {
                assertTrue(
                    rankingTree.contains(staker),
                    "Active staker not in ranking tree"
                );
                
                uint256 position = rankingTree.getPosition(staker);
                assertTrue(position > 0, "Active staker has invalid position");
            } else {
                assertTrue(
                    !rankingTree.contains(staker),
                    "Inactive staker still in ranking tree"
                );
            }
        }
    }
    
    /**
     * @notice Ranks must be unique and contiguous
     */
    function invariant_ranksUniqueAndContiguous() public view {
        uint256 total = staking.totalStakers();
        if (total == 0) return;
        
        bool[] memory rankSeen = new bool[](total + 1);
        
        for (uint256 i = 0; i < allStakers.length && i < total; i++) {
            address staker = allStakers[i];
            if (!isActiveStaker[staker]) continue;
            
            uint256 rank = staking.getRank(staker);
            assertTrue(rank > 0 && rank <= total, "Rank out of valid range");
            assertTrue(!rankSeen[rank], "Duplicate rank detected");
            rankSeen[rank] = true;
        }
        
        // Check all ranks are used (contiguous)
        for (uint256 r = 1; r <= total; r++) {
            assertTrue(rankSeen[r], "Gap in rank sequence");
        }
    }
    
    // =============================================================================
    // GAS/DOS INVARIANTS
    // =============================================================================
    
    /**
     * @notice Stake operation should have bounded gas cost
     * @dev From LayerEdge H-1: Cascading updates can exhaust gas
     */
    function invariant_stakeOperationGasBounded() public {
        address testStaker = actors[0];
        uint256 amount = 1 ether;
        
        vm.startPrank(testStaker);
        
        uint256 gasBefore = gasleft();
        try staking.stake(amount) {} catch {}
        uint256 gasUsed = gasBefore - gasleft();
        
        vm.stopPrank();
        
        // Max gas should be reasonable even with 1000+ stakers
        // O(log n) for tree operations, not O(n)
        uint256 maxExpectedGas = 500_000;
        assertTrue(
            gasUsed < maxExpectedGas,
            "Stake operation gas too high - possible cascading update issue"
        );
    }
    
    /**
     * @notice Tier recalculation should be O(1) or O(log n), not O(n)
     */
    function invariant_tierCalculationEfficient() public {
        uint256 total = staking.totalStakers();
        if (total == 0) return;
        
        address staker = allStakers[0];
        
        uint256 gasBefore = gasleft();
        staking.getTier(staker);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should be constant or logarithmic
        uint256 maxGas = 10_000;
        assertTrue(gasUsed < maxGas, "Tier lookup too expensive");
    }
    
    // =============================================================================
    // POSITION GAMING INVARIANTS
    // =============================================================================
    
    /**
     * @notice Staking order should determine rank (FCFS)
     */
    function invariant_fcfsOrderMaintained() public view {
        // Check that earlier stakers have lower (better) ranks
        // This is protocol-specific - adjust based on your FCFS rules
        
        uint256 prevRank = 0;
        for (uint256 i = 0; i < allStakers.length && i < 20; i++) {
            address staker = allStakers[i];
            if (!isActiveStaker[staker]) continue;
            
            uint256 rank = staking.getRank(staker);
            
            // For pure FCFS, earlier stakers should have lower ranks
            // (if stakes are equal)
            if (prevRank > 0) {
                // This check depends on specific FCFS rules
                // Adjust as needed for your protocol
            }
            
            prevRank = rank;
        }
    }
    
    // =============================================================================
    // HANDLER FUNCTIONS (for invariant fuzzing)
    // =============================================================================
    
    /**
     * @notice Handler: Stake tokens
     */
    function stake(uint256 actorIndex, uint256 amount) public {
        actorIndex = bound(actorIndex, 0, actors.length - 1);
        amount = bound(amount, staking.minStakeAmount(), 100 ether);
        
        address actor = actors[actorIndex];
        
        vm.startPrank(actor);
        try staking.stake(amount) {
            if (!isActiveStaker[actor]) {
                allStakers.push(actor);
                isActiveStaker[actor] = true;
            }
            totalTrackedStake += amount;
        } catch {}
        vm.stopPrank();
    }
    
    /**
     * @notice Handler: Unstake tokens
     */
    function unstake(uint256 actorIndex, uint256 amount) public {
        actorIndex = bound(actorIndex, 0, actors.length - 1);
        address actor = actors[actorIndex];
        
        uint256 currentStake = staking.getStakedAmount(actor);
        amount = bound(amount, 0, currentStake);
        
        vm.startPrank(actor);
        try staking.unstake(amount) {
            if (staking.getStakedAmount(actor) < staking.minStakeAmount()) {
                isActiveStaker[actor] = false;
            }
            totalTrackedStake -= amount;
        } catch {}
        vm.stopPrank();
    }
    
    /**
     * @notice Handler: Attempt ghost stake (stake 0 or below minimum)
     */
    function attemptGhostStake(uint256 actorIndex) public {
        actorIndex = bound(actorIndex, 0, actors.length - 1);
        address actor = actors[actorIndex];
        
        uint256 minStake = staking.minStakeAmount();
        uint256 ghostAmount = minStake > 0 ? minStake - 1 : 0;
        
        vm.startPrank(actor);
        try staking.stake(ghostAmount) {
            // If this succeeds, invariant_noGhostStakers should catch it
        } catch {
            // Expected - ghost stake should be rejected
        }
        vm.stopPrank();
    }
    
    /**
     * @notice Handler: Mass stake to test edge cases
     */
    function massStakeToEdgeCase(uint256 targetCount) public {
        // Target dangerous edge cases: 14, 24, 34, etc.
        targetCount = bound(targetCount, 14, 54);
        if (targetCount % 10 != 4) {
            targetCount = (targetCount / 10) * 10 + 4;
        }
        
        uint256 current = staking.totalStakers();
        
        while (current < targetCount && current < targetCount + 20) {
            uint256 actorIndex = current % actors.length;
            address actor = actors[actorIndex];
            
            vm.startPrank(actor);
            try staking.stake(1 ether) {
                if (!isActiveStaker[actor]) {
                    allStakers.push(actor);
                    isActiveStaker[actor] = true;
                }
            } catch {}
            vm.stopPrank();
            
            current = staking.totalStakers();
        }
    }
    
    // =============================================================================
    // HELPER FUNCTIONS
    // =============================================================================
    
    /**
     * @notice Count active stakers from our tracking
     */
    function countActiveStakers() internal view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < allStakers.length; i++) {
            if (isActiveStaker[allStakers[i]]) {
                count++;
            }
        }
        return count;
    }
}

// =============================================================================
// EXTENDED TEST: Tier Boundary Edge Case Fuzzing
// =============================================================================

contract TierBoundaryEdgeCaseTest is Test {
    /**
     * @notice Fuzz test for tier boundary calculation edge cases
     * @dev Specifically tests the 10N+4 pattern that caused LayerEdge H-2
     */
    function testFuzz_tierBoundaryAtEdgeCases(uint256 totalStakers) public {
        totalStakers = bound(totalStakers, 10, 1000);
        
        // Calculate boundaries using integer division
        uint256 tier1Boundary = (totalStakers * TIER1_PERCENT) / 100;
        uint256 tier2Cumulative = (totalStakers * (TIER1_PERCENT + TIER2_PERCENT)) / 100;
        
        // Calculate tier sizes
        uint256 tier1Size = tier1Boundary;
        uint256 tier2Size = tier2Cumulative - tier1Boundary;
        uint256 tier3Size = totalStakers - tier2Cumulative;
        
        // Invariants
        assertEq(tier1Size + tier2Size + tier3Size, totalStakers, "Tier sizes don't sum to total");
        assertTrue(tier1Size > 0 || totalStakers == 0, "Tier 1 is empty");
        
        // Check for edge case collisions
        if (totalStakers % 10 == 4) {
            // At these values, verify boundaries don't overlap incorrectly
            assertTrue(tier1Boundary < tier2Cumulative, "Tier 1/2 boundary collision at edge case");
        }
        
        // Log edge cases for manual review
        if (tier2Size == 0 && totalStakers > 10) {
            console.log("Warning: Empty tier 2 at totalStakers =", totalStakers);
        }
    }
    
    uint256 constant TIER1_PERCENT = 40;
    uint256 constant TIER2_PERCENT = 30;
}
