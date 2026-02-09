// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DeFiInvariantBase.sol";

/**
 * @title LendingInvariantTest
 * @author Smart Contract Auditor (ClawdEva)
 * @notice Template invariant tests for lending protocol contracts
 * @dev Copy and modify for your specific lending protocol
 * 
 * Key invariants tested:
 *   - Collateralization ratios
 *   - Interest rate monotonicity
 *   - Utilization bounds
 *   - Liquidation thresholds
 *   - Bad debt isolation
 */

// ============ Example Lending Interface ============
// Replace with your actual lending protocol interface

interface ILendingPool {
    function deposit(address asset, uint256 amount, address onBehalfOf) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function borrow(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf) external;
    function repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf) external returns (uint256);
    function liquidate(address collateral, address debt, address user, uint256 debtToCover) external;
    
    function getUserAccountData(address user) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    );
    
    function getReserveData(address asset) external view returns (
        uint256 totalLiquidity,
        uint256 totalBorrows,
        uint256 liquidityRate,
        uint256 borrowRate,
        uint256 liquidityIndex,
        uint256 borrowIndex
    );
}

/**
 * @title LendingHandler
 * @notice Handler for lending protocol actions
 */
contract LendingHandler is Test {
    ILendingPool public pool;
    IERC20Mintable public collateralToken;
    IERC20Mintable public debtToken;
    
    address[] public actors;
    
    // Ghost variables
    mapping(address => uint256) public ghost_userCollateral;
    mapping(address => uint256) public ghost_userDebt;
    uint256 public ghost_totalDeposits;
    uint256 public ghost_totalBorrows;
    uint256 public ghost_lastLiquidityIndex;
    uint256 public ghost_lastBorrowIndex;
    
    // Call tracking
    uint256 public depositCalls;
    uint256 public withdrawCalls;
    uint256 public borrowCalls;
    uint256 public repayCalls;
    uint256 public liquidateCalls;
    
    constructor(
        ILendingPool _pool,
        IERC20Mintable _collateral,
        IERC20Mintable _debt,
        address[] memory _actors
    ) {
        pool = _pool;
        collateralToken = _collateral;
        debtToken = _debt;
        actors = _actors;
    }
    
    // ============ Handler Functions ============
    
    function deposit(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        amount = bound(amount, 1e6, 1e24); // Min 1 USDC, max 1M tokens
        
        collateralToken.mint(actor, amount);
        
        vm.startPrank(actor);
        collateralToken.approve(address(pool), amount);
        pool.deposit(address(collateralToken), amount, actor);
        vm.stopPrank();
        
        ghost_userCollateral[actor] += amount;
        ghost_totalDeposits += amount;
        depositCalls++;
    }
    
    function withdraw(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        
        // Get user's available to withdraw (accounting for borrows)
        (uint256 totalCollateral, uint256 totalDebt,,,, uint256 healthFactor) = 
            pool.getUserAccountData(actor);
        
        if (totalCollateral == 0) return;
        
        // Calculate max withdrawal that maintains health factor > 1
        uint256 maxWithdraw = totalCollateral - totalDebt;
        if (maxWithdraw == 0) return;
        
        amount = bound(amount, 1, maxWithdraw);
        
        vm.prank(actor);
        uint256 withdrawn = pool.withdraw(address(collateralToken), amount, actor);
        
        ghost_userCollateral[actor] -= withdrawn;
        ghost_totalDeposits -= withdrawn;
        withdrawCalls++;
    }
    
    function borrow(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        
        // Get available borrows
        (,, uint256 availableBorrows,,,) = pool.getUserAccountData(actor);
        
        if (availableBorrows == 0) return;
        
        amount = bound(amount, 1, availableBorrows / 2); // Borrow up to 50% of available
        
        vm.prank(actor);
        pool.borrow(address(debtToken), amount, 2, actor); // 2 = variable rate
        
        ghost_userDebt[actor] += amount;
        ghost_totalBorrows += amount;
        borrowCalls++;
    }
    
    function repay(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        
        uint256 userDebt = ghost_userDebt[actor];
        if (userDebt == 0) return;
        
        amount = bound(amount, 1, userDebt);
        
        debtToken.mint(actor, amount);
        
        vm.startPrank(actor);
        debtToken.approve(address(pool), amount);
        uint256 repaid = pool.repay(address(debtToken), amount, 2, actor);
        vm.stopPrank();
        
        ghost_userDebt[actor] -= repaid;
        ghost_totalBorrows -= repaid;
        repayCalls++;
    }
    
    function liquidate(uint256 liquidatorSeed, uint256 targetSeed) external {
        address liquidator = actors[liquidatorSeed % actors.length];
        address target = actors[targetSeed % actors.length];
        
        if (liquidator == target) return;
        
        // Check if target is liquidatable
        (,,,,,uint256 healthFactor) = pool.getUserAccountData(target);
        
        if (healthFactor >= 1e18) return; // Not liquidatable
        
        uint256 debtToCover = ghost_userDebt[target] / 2; // Cover 50%
        if (debtToCover == 0) return;
        
        debtToken.mint(liquidator, debtToCover);
        
        vm.startPrank(liquidator);
        debtToken.approve(address(pool), debtToCover);
        pool.liquidate(address(collateralToken), address(debtToken), target, debtToCover);
        vm.stopPrank();
        
        liquidateCalls++;
    }
    
    // ============ Helpers ============
    
    function updateIndices() external {
        (,,,, uint256 liquidityIndex, uint256 borrowIndex) = 
            pool.getReserveData(address(collateralToken));
        
        ghost_lastLiquidityIndex = liquidityIndex;
        ghost_lastBorrowIndex = borrowIndex;
    }
    
    function getTotalCalls() external view returns (uint256) {
        return depositCalls + withdrawCalls + borrowCalls + repayCalls + liquidateCalls;
    }
}

/**
 * @title LendingInvariantTest
 * @notice Main lending protocol invariant test
 */
contract LendingInvariantTest is LendingInvariants {
    ILendingPool public pool;
    IERC20Mintable public collateralToken;
    IERC20Mintable public debtToken;
    LendingHandler public handler;
    
    uint256 public constant MAX_UTILIZATION_BPS = 9500; // 95%
    uint256 public constant LIQUIDATION_THRESHOLD_BPS = 8500; // 85%
    
    uint256 public lastLiquidityIndex;
    uint256 public lastBorrowIndex;
    
    function setUp() public {
        // ========================================
        // TODO: Deploy your lending pool here
        // ========================================
        // Example:
        // collateralToken = new MockERC20("Collateral", "COL", 18);
        // debtToken = new MockERC20("Debt", "DEBT", 18);
        // pool = new YourLendingPool(...);
        
        _addActors(5);
        
        handler = new LendingHandler(pool, collateralToken, debtToken, actors);
        
        targetContract(address(handler));
    }
    
    // ============ Invariants ============
    
    /// @notice Utilization rate should never exceed maximum
    function invariant_utilizationBounded() public view {
        (uint256 totalLiquidity, uint256 totalBorrows,,,,) = 
            pool.getReserveData(address(collateralToken));
        
        if (totalLiquidity == 0) {
            assertEq(totalBorrows, 0, "Borrows exist with no liquidity");
            return;
        }
        
        assertTrue(
            _checkUtilizationInvariant(totalLiquidity, totalBorrows, MAX_UTILIZATION_BPS),
            "Utilization exceeds maximum"
        );
    }
    
    /// @notice All positions must be adequately collateralized
    function invariant_allPositionsCollateralized() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            address user = actors[i];
            
            (uint256 collateral, uint256 debt,,,, uint256 healthFactor) = 
                pool.getUserAccountData(user);
            
            if (debt > 0) {
                // Health factor >= 1e18 means collateralized
                assertGe(healthFactor, 1e18, "Position undercollateralized");
                
                // Also check our invariant
                assertTrue(
                    _checkCollateralRatioInvariant(collateral, debt, LIQUIDATION_THRESHOLD_BPS),
                    "Collateral ratio violated"
                );
            }
        }
    }
    
    /// @notice Interest indices can only increase
    function invariant_interestIndicesMonotonic() public {
        (,,,, uint256 liquidityIndex, uint256 borrowIndex) = 
            pool.getReserveData(address(collateralToken));
        
        assertTrue(
            _checkInterestMonotonicInvariant(lastLiquidityIndex, liquidityIndex),
            "Liquidity index decreased"
        );
        
        assertTrue(
            _checkInterestMonotonicInvariant(lastBorrowIndex, borrowIndex),
            "Borrow index decreased"
        );
        
        lastLiquidityIndex = liquidityIndex;
        lastBorrowIndex = borrowIndex;
    }
    
    /// @notice Total deposits should always >= total borrows
    function invariant_depositsExceedBorrows() public view {
        (uint256 totalLiquidity, uint256 totalBorrows,,,,) = 
            pool.getReserveData(address(collateralToken));
        
        assertGe(
            totalLiquidity,
            totalBorrows,
            "Total borrows exceed total liquidity"
        );
    }
    
    /// @notice No position should have debt without collateral
    function invariant_noUnsecuredDebt() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            address user = actors[i];
            
            (uint256 collateral, uint256 debt,,,,) = pool.getUserAccountData(user);
            
            if (collateral == 0) {
                assertEq(debt, 0, "User has debt without collateral");
            }
        }
    }
    
    /// @notice Bad debt should be isolated (no protocol-wide contagion)
    function invariant_badDebtIsolated() public view {
        // Sum all user collateral and debt
        uint256 totalUserCollateral = 0;
        uint256 totalUserDebt = 0;
        
        for (uint256 i = 0; i < actors.length; i++) {
            (uint256 collateral, uint256 debt,,,,) = pool.getUserAccountData(actors[i]);
            totalUserCollateral += collateral;
            totalUserDebt += debt;
        }
        
        // If there's bad debt, it should be limited to specific users
        // not spread across the protocol
        if (totalUserDebt > totalUserCollateral) {
            // Bad debt exists - verify it's isolated
            // (This is a placeholder - implement protocol-specific check)
            console.log("Warning: Bad debt detected");
        }
    }
    
    /// @notice Interest rates should be within reasonable bounds
    function invariant_interestRatesBounded() public view {
        (,, uint256 liquidityRate, uint256 borrowRate,,) = 
            pool.getReserveData(address(collateralToken));
        
        // Max 1000% APY (expressed in RAY = 1e27)
        uint256 MAX_RATE = 10 * 1e27;
        
        assertLe(liquidityRate, MAX_RATE, "Liquidity rate too high");
        assertLe(borrowRate, MAX_RATE, "Borrow rate too high");
        
        // Borrow rate should always >= liquidity rate
        assertGe(borrowRate, liquidityRate, "Borrow rate < liquidity rate");
    }
    
    /// @notice Reserve factor should ensure protocol solvency
    function invariant_reserveAccounting() public view {
        (uint256 totalLiquidity, uint256 totalBorrows,,,,) = 
            pool.getReserveData(address(collateralToken));
        
        uint256 actualBalance = collateralToken.balanceOf(address(pool));
        
        // Available liquidity should equal actual balance
        uint256 availableLiquidity = totalLiquidity - totalBorrows;
        
        // Allow small rounding differences (< 0.01%)
        assertApproxEq(
            availableLiquidity,
            actualBalance,
            actualBalance / 10000,
            "Reserve accounting mismatch"
        );
    }
    
    // ============ Summary ============
    
    function invariant_callSummary() public view {
        console.log("=== Lending Invariant Test Summary ===");
        console.log("Deposit calls:", handler.depositCalls());
        console.log("Withdraw calls:", handler.withdrawCalls());
        console.log("Borrow calls:", handler.borrowCalls());
        console.log("Repay calls:", handler.repayCalls());
        console.log("Liquidate calls:", handler.liquidateCalls());
        console.log("Total calls:", handler.getTotalCalls());
        
        (uint256 liquidity, uint256 borrows,,,,) = pool.getReserveData(address(collateralToken));
        console.log("Final total liquidity:", liquidity);
        console.log("Final total borrows:", borrows);
        
        if (liquidity > 0) {
            console.log("Final utilization:", borrows * 100 / liquidity, "%");
        }
    }
}
