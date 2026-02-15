/**
 * Even more curated findings to reach 100+
 */

export const MORE_FINDINGS = [
  // Lending-specific
  {
    id: 'SOL-051',
    category: 'oracle',
    severity: 'critical',
    title: 'Liquidation at Stale Price During Flash Crash',
    protocol: 'Lending Protocol',
    platform: 'Immunefi',
    description: 'Oracle circuit breaker pins price at minAnswer during crash, but protocol liquidates at real price.',
    impact: 'Healthy positions liquidated at artificially low prices.',
    code: `// Oracle returns minAnswer during crash
// But AMM price keeps falling`,
    fix: `require(price > minAnswer && price < maxAnswer, "Price breaker");`,
  },
  {
    id: 'SOL-052',
    category: 'arithmetic',
    severity: 'high',
    title: 'Interest Rate Model Overflow at High Utilization',
    protocol: 'Lending Protocol',
    platform: 'Code4rena',
    description: 'Interest rate calculation overflows when utilization approaches 100%.',
    impact: 'Interest rate becomes 0 or negative at critical times.',
    code: `uint256 rate = baseRate + (utilization * multiplier / (1e18 - utilization));
// Overflow when utilization approaches 1e18`,
    fix: `require(utilization < MAX_UTILIZATION, "Utilization too high");`,
  },
  {
    id: 'SOL-053',
    category: 'access-control',
    severity: 'high',
    title: 'Liquidator Can Seize More Than Allowed',
    protocol: 'Lending Protocol',
    platform: 'Sherlock',
    description: 'No check that liquidator only seizes up to close factor of debt.',
    impact: 'Liquidator takes all collateral for partial debt repayment.',
    code: `function liquidate(address user, uint256 repayAmount) external {
    uint256 seizeTokens = repayAmount * price / collateralPrice;
    // No check that seizeTokens <= maxSeizable
}`,
    fix: `require(repayAmount <= debt * closeFactor / 1e18, "Exceeds close factor");`,
  },
  
  // Staking-specific
  {
    id: 'SOL-054',
    category: 'arithmetic',
    severity: 'high',
    title: 'Reward Distribution to Zero Stakers',
    protocol: 'Staking Protocol',
    platform: 'Code4rena',
    description: 'Rewards added when totalStaked = 0 are permanently lost.',
    impact: 'Protocol tokens stuck in contract forever.',
    code: `function notifyReward(uint256 amount) external {
    rewardPerToken += amount * 1e18 / totalStaked;  // Division by zero!
}`,
    fix: `require(totalStaked > 0, "No stakers");`,
  },
  {
    id: 'SOL-055',
    category: 'reentrancy',
    severity: 'high',
    title: 'Stake and Claim in Same Transaction',
    protocol: 'Staking Protocol',
    platform: 'Sherlock',
    description: 'User can stake and immediately claim rewards in same block.',
    impact: 'New stakers dilute existing stakers immediately.',
    code: `function stake(uint256 amount) external {
    _updateReward(msg.sender);  // Gets full pending rewards
    stakedBalance[msg.sender] += amount;
}`,
    fix: `// Use checkpoint that excludes current block rewards`,
  },
  
  // NFT-specific
  {
    id: 'SOL-056',
    category: 'reentrancy',
    severity: 'critical',
    title: 'NFT Rental Hijack via ERC721 Callback',
    protocol: 'NFT Rental',
    platform: 'Code4rena',
    description: 'Rental period extended during onERC721Received callback.',
    impact: 'Renter keeps NFT indefinitely by extending during return.',
    code: `function endRental() external {
    _safeTransfer(nft, renter, owner, tokenId);  // Callback to renter
    delete rentals[tokenId];  // State update after callback
}`,
    fix: `// Update state before transfer`,
  },
  {
    id: 'SOL-057',
    category: 'access-control',
    severity: 'high',
    title: 'NFT Approval Not Cleared on Transfer',
    protocol: 'NFT Protocol',
    platform: 'Sherlock',
    description: 'Token approvals persist after transfer, allowing previous owner access.',
    impact: 'Previous approved operator can take NFT from new owner.',
    code: `function transferFrom(address from, address to, uint256 id) external {
    // Missing: delete tokenApprovals[id]
    ownerOf[id] = to;
}`,
    fix: `delete tokenApprovals[id];`,
  },
  
  // AMM-specific
  {
    id: 'SOL-058',
    category: 'arithmetic',
    severity: 'critical',
    title: 'Concentrated Liquidity Position Theft',
    protocol: 'AMM Protocol',
    platform: 'Immunefi',
    description: 'Rounding error allows extracting more liquidity than deposited.',
    impact: 'Attacker drains pool via repeated add/remove.',
    code: `// Small positions round in attacker's favor
// 1000 iterations extracts significant value`,
    fix: `// Round against user in both add and remove`,
  },
  {
    id: 'SOL-059',
    category: 'flash-loan',
    severity: 'high',
    title: 'Just-in-Time Liquidity Attack',
    protocol: 'AMM Protocol',
    platform: 'Code4rena',
    description: 'Attacker adds liquidity just before large trade, removes after.',
    impact: 'MEV extraction from traders via JIT attack.',
    code: `// No time-weighted fee distribution
// Immediate fee accrual enables JIT`,
    fix: `// Implement fee delay or time-weighted distribution`,
  },
  
  // Perp-specific
  {
    id: 'SOL-060',
    category: 'oracle',
    severity: 'critical',
    title: 'Index Price vs Mark Price Arbitrage',
    protocol: 'Perp DEX',
    platform: 'Sherlock',
    description: 'Large gap between index and mark price exploitable.',
    impact: 'Attacker profits from index/mark divergence.',
    code: `// No cap on mark-index deviation
// Large positions can push mark far from index`,
    fix: `require(abs(markPrice - indexPrice) / indexPrice < MAX_DEVIATION);`,
  },
  {
    id: 'SOL-061',
    category: 'arithmetic',
    severity: 'high',
    title: 'Funding Rate Calculation Rounds to Zero',
    protocol: 'Perp DEX',
    platform: 'Code4rena',
    description: 'Small funding rate * small position = 0 due to rounding.',
    impact: 'Small positions never pay funding, imbalance accumulates.',
    code: `uint256 funding = position * rate / 1e18;  // Rounds to 0 for small`,
    fix: `// Accumulate funding internally before applying`,
  },
  
  // Bridge-specific
  {
    id: 'SOL-062',
    category: 'cross-chain',
    severity: 'critical',
    title: 'Token Decimal Mismatch Across Chains',
    protocol: 'Bridge Protocol',
    platform: 'Immunefi',
    description: 'Token has 18 decimals on source, 6 on destination.',
    impact: 'Bridging 1 token gives 1e12 tokens on destination.',
    code: `// Assumes same decimals on both chains
function bridge(uint256 amount) external {
    burn(amount);
    sendMessage(targetChain, amount);  // Same amount, different meaning
}`,
    fix: `// Include token decimals in message
// Normalize during bridge`,
  },
  {
    id: 'SOL-063',
    category: 'cross-chain',
    severity: 'high',
    title: 'Gas Limit Too Low for Complex Execution',
    protocol: 'Bridge Protocol',
    platform: 'Code4rena',
    description: 'Fixed gas limit insufficient for complex receiver logic.',
    impact: 'Message delivered but execution fails, funds stuck.',
    code: `function receiveMessage(bytes calldata data) external {
    (bool success,) = target.call{gas: 100000}(data);  // Fixed gas
    // Complex operations may need more
}`,
    fix: `// Allow gas limit to be specified per message
// Or implement retry mechanism`,
  },
  
  // Governance-specific
  {
    id: 'SOL-064',
    category: 'governance',
    severity: 'critical',
    title: 'Proposal Can Drain Treasury',
    protocol: 'DAO Protocol',
    platform: 'Code4rena',
    description: 'No validation that proposal actions are reasonable.',
    impact: 'Malicious proposal can transfer all treasury funds.',
    code: `function execute(uint256 proposalId) external {
    Proposal memory p = proposals[proposalId];
    require(p.votes > quorum);
    target.call(p.calldata);  // Arbitrary call to any target
}`,
    fix: `// Validate targets are approved
// Limit single transaction amounts`,
  },
  {
    id: 'SOL-065',
    category: 'governance',
    severity: 'high',
    title: 'Vote Delegation Infinite Loop',
    protocol: 'DAO Protocol',
    platform: 'Sherlock',
    description: 'Circular delegation creates infinite loop in vote counting.',
    impact: 'Vote counting function reverts, governance frozen.',
    code: `function getVotes(address user) public view returns (uint256) {
    if (delegates[user] != address(0)) {
        return getVotes(delegates[user]);  // Can loop forever
    }
    return balanceOf[user];
}`,
    fix: `// Track visited addresses to detect cycles`,
  },
  
  // Vault-specific  
  {
    id: 'SOL-066',
    category: 'arithmetic',
    severity: 'critical',
    title: 'ERC4626 Share Inflation via Donation',
    protocol: 'Vault Protocol',
    platform: 'Sherlock',
    description: 'First depositor donates to inflate share price, subsequent depositors get 0 shares.',
    impact: 'Up to 100% theft of subsequent deposits.',
    code: `// Attacker: deposit 1 wei, donate 1e18 tokens
// Victim deposits 0.5e18, gets 0 shares`,
    fix: `// Virtual shares offset
function _convertToShares(uint256 assets) internal view returns (uint256) {
    return assets.mulDiv(totalSupply() + 1e3, totalAssets() + 1);
}`,
  },
  {
    id: 'SOL-067',
    category: 'access-control',
    severity: 'high',
    title: 'Vault Deposit When Paused Still Possible',
    protocol: 'Vault Protocol',
    platform: 'Code4rena',
    description: 'Pause only affects withdraw, not deposit.',
    impact: 'Users deposit into paused vault, funds stuck.',
    code: `function withdraw(uint256 assets) external whenNotPaused { ... }
function deposit(uint256 assets) external { ... }  // No pause check`,
    fix: `function deposit(uint256 assets) external whenNotPaused { ... }`,
  },
  
  // Token-specific additions
  {
    id: 'SOL-068',
    category: 'token',
    severity: 'high',
    title: 'Blocklist Token Transfer Reverts',
    protocol: 'DeFi Protocol',
    platform: 'Sherlock',
    description: 'Transfer to blocklisted address reverts entire operation.',
    impact: 'Blocked user can grief all distributions.',
    code: `function distribute(address[] calldata users) external {
    for (uint i = 0; i < users.length; i++) {
        usdc.transfer(users[i], amounts[i]);  // Reverts if any blocklisted
    }
}`,
    fix: `// Skip failed transfers or use pull pattern`,
  },
  {
    id: 'SOL-069',
    category: 'token',
    severity: 'medium',
    title: 'Token With Multiple Addresses',
    protocol: 'DEX Protocol',
    platform: 'Code4rena',
    description: 'Same token accessible via multiple addresses (e.g., proxy + implementation).',
    impact: 'Attacker creates duplicate pools, extracts arbitrage.',
    code: `// Two pools for same underlying token
// Attacker arbitrages between them`,
    fix: `// Canonicalize token addresses
// Block proxy addresses`,
  },
  
  // Signature additions
  {
    id: 'SOL-070',
    category: 'signature',
    severity: 'critical',
    title: 'Permit2 SignatureDeadline Not Enforced',
    protocol: 'DeFi Protocol',
    platform: 'Code4rena',
    description: 'Protocol checks Permit2 permit but ignores expiration.',
    impact: 'Old signatures valid indefinitely.',
    code: `permit2.permit(owner, permitted, signature);
// Not checking: permitted.deadline`,
    fix: `require(permitted.deadline >= block.timestamp, "Expired");`,
  },
  
  // DoS additions
  {
    id: 'SOL-071',
    category: 'dos',
    severity: 'high',
    title: 'Array Pop in Loop Modifies Length',
    protocol: 'Registry Protocol',
    platform: 'Sherlock',
    description: 'Removing elements while iterating causes skip or out-of-bounds.',
    impact: 'Some elements never processed, or function reverts.',
    code: `for (uint i = 0; i < items.length; i++) {
    if (shouldRemove(items[i])) {
        items[i] = items[items.length - 1];
        items.pop();  // Length changes!
    }
}`,
    fix: `// Iterate backwards or use separate removal list`,
  },
  {
    id: 'SOL-072',
    category: 'dos',
    severity: 'medium',
    title: 'Return Bomb Attack',
    protocol: 'DeFi Protocol',
    platform: 'Code4rena',
    description: 'Malicious contract returns huge data, consuming caller\'s gas.',
    impact: 'Operations revert due to return data copy cost.',
    code: `(bool success, bytes memory data) = target.call(calldata);
// Attacker returns 1MB, consuming gas on copy`,
    fix: `// Limit return data size
assembly {
    success := call(gas(), target, 0, add(calldata, 0x20), mload(calldata), 0, 0)
    let size := returndatasize()
    if gt(size, MAX_RETURN) { size := MAX_RETURN }
    data := mload(0x40)
    returndatacopy(add(data, 0x20), 0, size)
}`,
  },
  
  // Flash loan additions
  {
    id: 'SOL-073',
    category: 'flash-loan',
    severity: 'high',
    title: 'Read-Only Reentrancy via Balancer Vault',
    protocol: 'Lending Protocol',
    platform: 'Sherlock',
    description: 'Protocol reads pool state during Balancer callback when invariants broken.',
    impact: 'Manipulated collateral values enable bad debt.',
    code: `// During Balancer swap callback:
uint256 value = balancerPool.getRate() * balance;  // Rate is wrong!`,
    fix: `// Check Balancer vault reentrancy lock
// Or use external oracle`,
  },
  
  // Additional critical findings
  {
    id: 'SOL-074',
    category: 'upgrade',
    severity: 'critical',
    title: 'Transparent Proxy Admin Collision',
    protocol: 'Upgradeable Protocol',
    platform: 'Immunefi',
    description: 'Admin slot collides with implementation storage.',
    impact: 'Upgrade corrupts implementation state.',
    code: `// Incorrect admin slot calculation
bytes32 ADMIN_SLOT = keccak256("admin");  // Collides!`,
    fix: `// Use EIP-1967 slots
bytes32 ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;`,
  },
  {
    id: 'SOL-075',
    category: 'access-control',
    severity: 'critical',
    title: 'Timelock Execute Without Queue',
    protocol: 'Governance Protocol',
    platform: 'Code4rena',
    description: 'Execute function doesn\'t verify transaction was queued.',
    impact: 'Immediate execution bypasses timelock.',
    code: `function execute(bytes32 txHash) external {
    // Missing: require(queuedAt[txHash] != 0)
    require(block.timestamp >= eta[txHash], "Not ready");
    _execute(txHash);
}`,
    fix: `require(queuedAt[txHash] != 0, "Not queued");`,
  },
];
