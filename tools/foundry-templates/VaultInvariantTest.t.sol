// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DeFiInvariantBase.sol";

/**
 * @title VaultInvariantTest
 * @author Smart Contract Auditor (ClawdEva)
 * @notice Example invariant test for ERC-4626 vault contracts
 * @dev Copy and modify this template for your specific vault
 * 
 * To use:
 *   1. Replace YourVault with your vault contract
 *   2. Replace YourAsset with your underlying asset
 *   3. Add any protocol-specific invariants
 *   4. Run: forge test --match-contract VaultInvariantTest
 */

// ============ Example Vault Interface ============
// Replace with your actual vault interface
interface IVault is IERC4626 {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function mint(uint256 shares, address receiver) external returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
    function asset() external view returns (address);
}

interface IERC20Mintable is IERC20 {
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/**
 * @title VaultHandler
 * @notice Handler contract for vault operations
 * @dev Wraps vault calls with ghost variable tracking
 */
contract VaultHandler is Test {
    IVault public vault;
    IERC20Mintable public asset;
    
    // Ghost variables
    mapping(address => uint256) public ghost_userShares;
    mapping(address => uint256) public ghost_userDeposits;
    uint256 public ghost_totalDeposits;
    uint256 public ghost_totalShares;
    
    // Call tracking
    uint256 public depositCalls;
    uint256 public withdrawCalls;
    uint256 public mintCalls;
    uint256 public redeemCalls;
    
    // Actors
    address[] public actors;
    
    constructor(IVault _vault, IERC20Mintable _asset, address[] memory _actors) {
        vault = _vault;
        asset = _asset;
        actors = _actors;
    }
    
    // ============ Handler Functions ============
    
    function deposit(uint256 actorSeed, uint256 assets) external {
        address actor = actors[actorSeed % actors.length];
        assets = bound(assets, 1, 1e24); // Bound to reasonable range
        
        // Mint assets to actor
        asset.mint(actor, assets);
        
        vm.startPrank(actor);
        asset.approve(address(vault), assets);
        
        uint256 sharesBefore = vault.balanceOf(actor);
        uint256 shares = vault.deposit(assets, actor);
        uint256 sharesAfter = vault.balanceOf(actor);
        
        vm.stopPrank();
        
        // Update ghost variables
        ghost_userDeposits[actor] += assets;
        ghost_userShares[actor] += shares;
        ghost_totalDeposits += assets;
        ghost_totalShares += shares;
        depositCalls++;
        
        // Verify shares received
        assertEq(sharesAfter - sharesBefore, shares, "Shares mismatch");
    }
    
    function withdraw(uint256 actorSeed, uint256 assets) external {
        address actor = actors[actorSeed % actors.length];
        
        // Bound to actor's withdrawable amount
        uint256 maxAssets = vault.convertToAssets(vault.balanceOf(actor));
        if (maxAssets == 0) return; // Skip if nothing to withdraw
        
        assets = bound(assets, 1, maxAssets);
        
        vm.startPrank(actor);
        
        uint256 sharesBefore = vault.balanceOf(actor);
        uint256 shares = vault.withdraw(assets, actor, actor);
        uint256 sharesAfter = vault.balanceOf(actor);
        
        vm.stopPrank();
        
        // Update ghost variables
        ghost_userShares[actor] -= shares;
        ghost_totalShares -= shares;
        withdrawCalls++;
        
        // Verify shares burned
        assertEq(sharesBefore - sharesAfter, shares, "Shares burn mismatch");
    }
    
    function mint(uint256 actorSeed, uint256 shares) external {
        address actor = actors[actorSeed % actors.length];
        shares = bound(shares, 1, 1e24);
        
        // Calculate required assets
        uint256 assetsNeeded = vault.previewMint(shares);
        asset.mint(actor, assetsNeeded);
        
        vm.startPrank(actor);
        asset.approve(address(vault), assetsNeeded);
        
        uint256 assets = vault.mint(shares, actor);
        
        vm.stopPrank();
        
        // Update ghost variables
        ghost_userDeposits[actor] += assets;
        ghost_userShares[actor] += shares;
        ghost_totalDeposits += assets;
        ghost_totalShares += shares;
        mintCalls++;
    }
    
    function redeem(uint256 actorSeed, uint256 shares) external {
        address actor = actors[actorSeed % actors.length];
        
        // Bound to actor's balance
        uint256 maxShares = vault.balanceOf(actor);
        if (maxShares == 0) return;
        
        shares = bound(shares, 1, maxShares);
        
        vm.startPrank(actor);
        
        uint256 assets = vault.redeem(shares, actor, actor);
        
        vm.stopPrank();
        
        // Update ghost variables
        ghost_userShares[actor] -= shares;
        ghost_totalShares -= shares;
        redeemCalls++;
    }
    
    // ============ Helpers ============
    
    function getActorCount() external view returns (uint256) {
        return actors.length;
    }
    
    function getTotalCalls() external view returns (uint256) {
        return depositCalls + withdrawCalls + mintCalls + redeemCalls;
    }
}

/**
 * @title VaultInvariantTest
 * @notice Main invariant test contract
 */
contract VaultInvariantTest is VaultInvariants {
    IVault public vault;
    IERC20Mintable public asset;
    VaultHandler public handler;
    
    function setUp() public {
        // ========================================
        // TODO: Deploy your vault and asset here
        // ========================================
        // Example:
        // asset = new MockERC20("Test", "TST", 18);
        // vault = new YourVault(address(asset));
        
        // Set up actors
        _addActors(5);
        
        // Deploy handler
        handler = new VaultHandler(vault, asset, actors);
        
        // Target the handler for invariant testing
        targetContract(address(handler));
        
        // Optionally exclude specific functions
        // excludeSelector(address(handler), handler.someFunction.selector);
    }
    
    // ============ Invariants ============
    
    /// @notice Total shares should match sum of all user shares
    function invariant_totalSharesMatchUserShares() public view {
        uint256 totalSupply = vault.totalSupply();
        uint256 sumUserShares = 0;
        
        for (uint256 i = 0; i < actors.length; i++) {
            sumUserShares += vault.balanceOf(actors[i]);
        }
        
        // Add handler's tracked shares
        assertEq(totalSupply, sumUserShares, "Total supply != sum of user balances");
    }
    
    /// @notice Vault total assets should equal underlying balance
    function invariant_totalAssetsMatchBalance() public view {
        uint256 reportedAssets = vault.totalAssets();
        uint256 actualBalance = asset.balanceOf(address(vault));
        
        // Assets should be <= actual balance (could be less due to unrealized losses)
        assertLe(reportedAssets, actualBalance + 1, "Reported assets > actual balance");
    }
    
    /// @notice Share value should never decrease unfairly (no free money)
    function invariant_noShareValueInflation() public view {
        uint256 totalSupply = vault.totalSupply();
        if (totalSupply == 0) return;
        
        uint256 totalAssets = vault.totalAssets();
        
        // Assets per share should be reasonable
        uint256 assetsPerShare = totalAssets * 1e18 / totalSupply;
        
        // Should not exceed some maximum (e.g., 1000x initial value)
        assertLt(assetsPerShare, 1e21, "Share value suspiciously high");
    }
    
    /// @notice convertToAssets and convertToShares should be consistent
    function invariant_conversionConsistency() public view {
        uint256 testShares = 1e18;
        uint256 testAssets = 1e18;
        
        uint256 assetsFromShares = vault.convertToAssets(testShares);
        uint256 sharesFromAssets = vault.convertToShares(testAssets);
        
        // Round-trip should not create value
        uint256 sharesBack = vault.convertToShares(assetsFromShares);
        uint256 assetsBack = vault.convertToAssets(sharesFromAssets);
        
        assertLe(sharesBack, testShares + 1, "Round-trip created shares");
        assertLe(assetsBack, testAssets + 1, "Round-trip created assets");
    }
    
    /// @notice Preview functions should match actual operations (approximately)
    function invariant_previewAccuracy() public view {
        uint256 testAmount = 1e18;
        
        uint256 previewDepositShares = vault.previewDeposit(testAmount);
        uint256 previewMintAssets = vault.previewMint(testAmount);
        
        // Preview should be non-zero for non-zero input (unless vault is empty/paused)
        if (vault.totalSupply() > 0 && vault.totalAssets() > 0) {
            assertGt(previewDepositShares, 0, "Preview deposit returns 0");
            assertGt(previewMintAssets, 0, "Preview mint returns 0");
        }
    }
    
    /// @notice First depositor attack check
    function invariant_noFirstDepositorAttack() public view {
        uint256 totalSupply = vault.totalSupply();
        uint256 totalAssets = vault.totalAssets();
        
        if (totalSupply > 0) {
            // Check that assets per share is reasonable
            // First depositor attack inflates this ratio
            uint256 ratio = totalAssets * 1e18 / totalSupply;
            
            // Should be within reasonable bounds (0.001x to 1000x)
            assertGt(ratio, 1e12, "Suspiciously low asset/share ratio");
            assertLt(ratio, 1e24, "Suspiciously high asset/share ratio");
        }
    }
    
    // ============ Postconditions ============
    
    /// @notice Log statistics after test
    function invariant_callSummary() public view {
        console.log("=== Vault Invariant Test Summary ===");
        console.log("Deposit calls:", handler.depositCalls());
        console.log("Withdraw calls:", handler.withdrawCalls());
        console.log("Mint calls:", handler.mintCalls());
        console.log("Redeem calls:", handler.redeemCalls());
        console.log("Total calls:", handler.getTotalCalls());
        console.log("Final total supply:", vault.totalSupply());
        console.log("Final total assets:", vault.totalAssets());
    }
}
