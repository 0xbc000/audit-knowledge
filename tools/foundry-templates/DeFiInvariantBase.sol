// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title DeFiInvariantBase
 * @author Smart Contract Auditor (ClawdEva)
 * @notice Base contract for DeFi protocol invariant testing
 * @dev Inherit from this contract and implement protocol-specific invariants
 * 
 * Usage:
 *   1. Inherit from DeFiInvariantBase
 *   2. Set up your protocol contracts in setUp()
 *   3. Create handler contracts for actions
 *   4. Implement invariant_ functions for your protocol
 *   5. Run: forge test --match-test invariant
 */
abstract contract DeFiInvariantBase is Test {
    
    // ============ State Variables ============
    
    /// @notice Track all actors/users in the system
    address[] internal actors;
    
    /// @notice Current actor for handler calls
    address internal currentActor;
    
    /// @notice Ghost variables for tracking expected state
    mapping(address => uint256) internal ghost_userDeposits;
    mapping(address => uint256) internal ghost_userWithdrawals;
    uint256 internal ghost_totalDeposits;
    uint256 internal ghost_totalWithdrawals;
    
    /// @notice Track call counts for coverage
    mapping(bytes4 => uint256) internal callCounts;
    
    // ============ Setup Helpers ============
    
    /// @notice Add actors for invariant testing
    function _addActors(uint256 count) internal {
        for (uint256 i = 0; i < count; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor", i)));
            actors.push(actor);
            vm.deal(actor, 100 ether);
        }
    }
    
    /// @notice Select a random actor
    function _selectActor(uint256 seed) internal returns (address) {
        currentActor = actors[seed % actors.length];
        vm.startPrank(currentActor);
        return currentActor;
    }
    
    /// @notice Stop pranking current actor
    function _stopActor() internal {
        vm.stopPrank();
    }
    
    // ============ Bound Helpers ============
    
    /// @notice Bound value to reasonable range
    function _boundAmount(uint256 amount, uint256 min, uint256 max) internal pure returns (uint256) {
        return bound(amount, min, max);
    }
    
    /// @notice Bound to non-zero amount
    function _boundNonZero(uint256 amount, uint256 max) internal pure returns (uint256) {
        return bound(amount, 1, max);
    }
    
    // ============ Assertion Helpers ============
    
    /// @notice Assert approximate equality with tolerance
    function assertApproxEq(uint256 a, uint256 b, uint256 tolerance, string memory message) internal pure {
        uint256 diff = a > b ? a - b : b - a;
        require(diff <= tolerance, message);
    }
    
    /// @notice Assert value within percentage range
    function assertWithinPercent(uint256 value, uint256 expected, uint256 percentBps) internal pure {
        uint256 tolerance = expected * percentBps / 10000;
        assertApproxEq(value, expected, tolerance, "Value outside percentage tolerance");
    }
    
    // ============ Logging Helpers ============
    
    /// @notice Log invariant check
    function _logInvariantCheck(string memory name, bool passed) internal view {
        if (!passed) {
            console.log("INVARIANT VIOLATED:", name);
        }
    }
    
    /// @notice Log call counts at end of test
    function _logCallCounts() internal view {
        console.log("=== Call Counts ===");
        // Override in child to log specific functions
    }
}

/**
 * @title AccountingInvariants
 * @notice Common accounting invariants for DeFi protocols
 */
abstract contract AccountingInvariants is DeFiInvariantBase {
    
    /// @notice Total supply should equal sum of all balances
    function _checkTotalSupplyInvariant(
        address token,
        address[] memory holders
    ) internal view returns (bool) {
        uint256 totalSupply = IERC20(token).totalSupply();
        uint256 sumBalances = 0;
        
        for (uint256 i = 0; i < holders.length; i++) {
            sumBalances += IERC20(token).balanceOf(holders[i]);
        }
        
        return totalSupply >= sumBalances;
    }
    
    /// @notice Deposits - Withdrawals = Current Balance
    function _checkDepositWithdrawInvariant(
        uint256 currentBalance
    ) internal view returns (bool) {
        return ghost_totalDeposits >= ghost_totalWithdrawals &&
               currentBalance == ghost_totalDeposits - ghost_totalWithdrawals;
    }
    
    /// @notice No value created from nothing
    function _checkNoFreeMoney(
        uint256 totalAssetsBefore,
        uint256 totalAssetsAfter,
        uint256 externalInflow
    ) internal pure returns (bool) {
        return totalAssetsAfter <= totalAssetsBefore + externalInflow;
    }
}

/**
 * @title AccessControlInvariants
 * @notice Common access control invariants
 */
abstract contract AccessControlInvariants is DeFiInvariantBase {
    
    address internal admin;
    mapping(bytes32 => mapping(address => bool)) internal roleMembers;
    
    /// @notice Admin should never be zero address after initialization
    function _checkAdminNotZero() internal view returns (bool) {
        return admin != address(0);
    }
    
    /// @notice Only designated roles can call protected functions
    function _checkRoleProtection(
        bytes32 role,
        address caller,
        bool callSucceeded
    ) internal view returns (bool) {
        if (!roleMembers[role][caller] && callSucceeded) {
            return false; // Unauthorized call succeeded - BAD
        }
        return true;
    }
}

/**
 * @title VaultInvariants
 * @notice Invariants specific to vault/ERC-4626 contracts
 */
abstract contract VaultInvariants is AccountingInvariants {
    
    /// @notice shares * totalAssets / totalSupply = user's asset value
    function _checkShareValueInvariant(
        address vault,
        address user
    ) internal view returns (bool) {
        uint256 userShares = IERC4626(vault).balanceOf(user);
        uint256 totalShares = IERC4626(vault).totalSupply();
        uint256 totalAssets = IERC4626(vault).totalAssets();
        
        if (totalShares == 0) return true;
        
        uint256 expectedAssets = userShares * totalAssets / totalShares;
        uint256 actualAssets = IERC4626(vault).convertToAssets(userShares);
        
        // Allow 1 wei rounding difference
        return actualAssets >= expectedAssets - 1 && 
               actualAssets <= expectedAssets + 1;
    }
    
    /// @notice Preview functions should not revert for valid inputs
    function _checkPreviewFunctions(
        address vault,
        uint256 amount
    ) internal view returns (bool) {
        try IERC4626(vault).previewDeposit(amount) returns (uint256) {
            // Success
        } catch {
            return false;
        }
        
        try IERC4626(vault).previewMint(amount) returns (uint256) {
            // Success
        } catch {
            return false;
        }
        
        return true;
    }
    
    /// @notice Deposit and redeem should be inverse operations
    function _checkDepositRedeemInverse(
        address vault,
        uint256 assetsIn,
        uint256 sharesOut,
        uint256 assetsBack
    ) internal pure returns (bool) {
        // Assets returned should be at most assets deposited (minus fees)
        return assetsBack <= assetsIn;
    }
}

/**
 * @title LendingInvariants
 * @notice Invariants specific to lending protocols
 */
abstract contract LendingInvariants is AccountingInvariants {
    
    /// @notice Total borrows <= total deposits * utilization cap
    function _checkUtilizationInvariant(
        uint256 totalDeposits,
        uint256 totalBorrows,
        uint256 maxUtilizationBps
    ) internal pure returns (bool) {
        if (totalDeposits == 0) return totalBorrows == 0;
        
        uint256 utilizationBps = totalBorrows * 10000 / totalDeposits;
        return utilizationBps <= maxUtilizationBps;
    }
    
    /// @notice Each position: collateral value * LTV >= debt value
    function _checkCollateralRatioInvariant(
        uint256 collateralValue,
        uint256 debtValue,
        uint256 ltvBps
    ) internal pure returns (bool) {
        if (debtValue == 0) return true;
        
        uint256 maxDebt = collateralValue * ltvBps / 10000;
        return debtValue <= maxDebt;
    }
    
    /// @notice Interest can only increase, never decrease
    function _checkInterestMonotonicInvariant(
        uint256 previousIndex,
        uint256 currentIndex
    ) internal pure returns (bool) {
        return currentIndex >= previousIndex;
    }
    
    /// @notice Liquidation should only happen when underwater
    function _checkLiquidationThresholdInvariant(
        uint256 collateralValue,
        uint256 debtValue,
        uint256 liquidationThresholdBps,
        bool liquidationHappened
    ) internal pure returns (bool) {
        uint256 healthFactor = collateralValue * 10000 / debtValue;
        
        if (liquidationHappened) {
            // If liquidation happened, health factor should be < threshold
            return healthFactor < liquidationThresholdBps;
        }
        return true;
    }
}

/**
 * @title DEXInvariants
 * @notice Invariants specific to DEX/AMM protocols
 */
abstract contract DEXInvariants is AccountingInvariants {
    
    /// @notice x * y = k (constant product invariant)
    function _checkConstantProductInvariant(
        uint256 reserve0Before,
        uint256 reserve1Before,
        uint256 reserve0After,
        uint256 reserve1After
    ) internal pure returns (bool) {
        uint256 kBefore = reserve0Before * reserve1Before;
        uint256 kAfter = reserve0After * reserve1After;
        
        // k should never decrease (can increase with fees)
        return kAfter >= kBefore;
    }
    
    /// @notice Output amount should never exceed input * price - fee
    function _checkSwapOutputInvariant(
        uint256 amountIn,
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut,
        uint256 feeBps
    ) internal pure returns (bool) {
        // Calculate expected output with fee
        uint256 amountInWithFee = amountIn * (10000 - feeBps);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 10000 + amountInWithFee;
        uint256 expectedOut = numerator / denominator;
        
        // Actual output should be <= expected (rounding down)
        return amountOut <= expectedOut;
    }
    
    /// @notice LP tokens should represent proportional ownership
    function _checkLPValueInvariant(
        uint256 lpBalance,
        uint256 totalLP,
        uint256 totalValue
    ) internal pure returns (bool) {
        if (totalLP == 0) return lpBalance == 0;
        
        uint256 expectedValue = lpBalance * totalValue / totalLP;
        // LP value should be positive if holding LP tokens
        return lpBalance == 0 || expectedValue > 0;
    }
}

// ============ Interfaces ============

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC4626 is IERC20 {
    function totalAssets() external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
    function previewDeposit(uint256 assets) external view returns (uint256);
    function previewMint(uint256 shares) external view returns (uint256);
    function previewWithdraw(uint256 assets) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
}
