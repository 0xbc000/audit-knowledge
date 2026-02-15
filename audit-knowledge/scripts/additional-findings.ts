/**
 * Additional curated findings to expand the database
 */

export const ADDITIONAL_FINDINGS = [
  // More Reentrancy
  {
    id: 'SOL-021',
    category: 'reentrancy',
    severity: 'critical',
    title: 'ERC721 onERC721Received Callback Reentrancy',
    protocol: 'NFT Marketplace',
    platform: 'Code4rena',
    description: 'Minting or transferring NFTs triggers onERC721Received callback before state is updated.',
    impact: 'Attacker can mint unlimited NFTs or manipulate auction state.',
    code: `function mint(address to) external {
    _safeMint(to, tokenId);  // Callback before state update
    totalMinted++;
}`,
    fix: `function mint(address to) external nonReentrant {
    totalMinted++;  // State first
    _safeMint(to, tokenId);
}`,
  },
  {
    id: 'SOL-022',
    category: 'reentrancy',
    severity: 'high',
    title: 'ERC1155 Batch Callback Reentrancy',
    protocol: 'Gaming Protocol',
    platform: 'Sherlock',
    description: 'ERC1155 safeBatchTransferFrom triggers callback that can re-enter during multi-token transfer.',
    impact: 'Attacker can receive extra tokens or manipulate game state.',
    code: `function batchTransfer(address to, uint256[] ids, uint256[] amounts) external {
    for (uint i = 0; i < ids.length; i++) {
        balances[msg.sender][ids[i]] -= amounts[i];
    }
    _safeBatchTransferFrom(msg.sender, to, ids, amounts, "");  // Callback
}`,
    fix: `// Use checks-effects-interactions or nonReentrant`,
  },
  {
    id: 'SOL-023',
    category: 'reentrancy',
    severity: 'critical',
    title: 'Reentrancy Guard Reset in receive()',
    protocol: 'Wise Lending',
    platform: 'Code4rena',
    description: 'Native token receive() function resets reentrancy guard, allowing re-entry through ETH transfer.',
    impact: 'Complete bypass of reentrancy protection.',
    code: `receive() external payable {
    _sendingProgress = false;  // Resets guard!
}`,
    fix: `// Never reset reentrancy state in receive()
// Use separate tracking for ETH flows`,
  },
  
  // More Oracle
  {
    id: 'SOL-024',
    category: 'oracle',
    severity: 'high',
    title: 'L2 Sequencer Downtime Not Checked',
    protocol: 'Lending Protocol',
    platform: 'Sherlock',
    description: 'On Arbitrum/Optimism, Chainlink prices may appear fresh but are stale if sequencer is down.',
    impact: 'Users liquidated at stale prices during sequencer outage.',
    code: `// Missing sequencer check on L2
(, int256 price, , uint256 updatedAt,) = feed.latestRoundData();`,
    fix: `(, int256 answer, uint256 startedAt,,) = sequencerFeed.latestRoundData();
require(answer == 0, "Sequencer down");
require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period");`,
  },
  {
    id: 'SOL-025',
    category: 'oracle',
    severity: 'medium',
    title: 'Hardcoded Oracle Decimals',
    protocol: 'DeFi Protocol',
    platform: 'Code4rena',
    description: 'Protocol assumes all Chainlink feeds return 8 decimals, but some return 18.',
    impact: 'Prices off by factor of 10^10 for non-8-decimal feeds.',
    code: `uint256 price = uint256(answer) * 1e10;  // Assumes 8 decimals`,
    fix: `uint8 decimals = feed.decimals();
uint256 price = uint256(answer) * 10**(18 - decimals);`,
  },
  {
    id: 'SOL-026',
    category: 'oracle',
    severity: 'high',
    title: 'Uniswap V3 TWAP Manipulation via Low Liquidity',
    protocol: 'Lending Protocol',
    platform: 'Sherlock',
    description: 'TWAP from low-liquidity Uniswap V3 pool can be manipulated cost-effectively.',
    impact: 'Attacker manipulates collateral price for profitable borrowing.',
    code: `// Using TWAP from pool with only $10k liquidity
(int24 tick,) = pool.observe([TWAP_PERIOD, 0]);`,
    fix: `// Validate minimum liquidity
require(pool.liquidity() >= MIN_LIQUIDITY, "Insufficient liquidity");
// Or use Chainlink as primary oracle`,
  },
  
  // More Access Control
  {
    id: 'SOL-027',
    category: 'access-control',
    severity: 'critical',
    title: 'LayerZero setTrustedRemote No Access Control',
    protocol: 'Cross-chain Protocol',
    platform: 'Code4rena',
    description: 'Function to set trusted remote chain address lacks owner check.',
    impact: 'Attacker can add malicious remote, stealing bridged funds.',
    code: `function setTrustedRemote(uint16 chainId, bytes calldata path) external {
    trustedRemote[chainId] = path;  // No onlyOwner!
}`,
    fix: `function setTrustedRemote(uint16 chainId, bytes calldata path) external onlyOwner {
    trustedRemote[chainId] = path;
}`,
  },
  {
    id: 'SOL-028',
    category: 'access-control',
    severity: 'high',
    title: 'First Depositor Controls Pool Parameters',
    protocol: 'AMM Protocol',
    platform: 'Sherlock',
    description: 'First depositor in new pool can set initial price and parameters.',
    impact: 'First depositor extracts value from subsequent depositors.',
    code: `function initializePool(uint256 priceX96) external {
    require(liquidity == 0, "Already initialized");
    sqrtPriceX96 = priceX96;  // Anyone can set initial price
}`,
    fix: `function initializePool(uint256 priceX96) external onlyFactory {
    // Only factory can initialize with validated price
}`,
  },
  
  // More Flash Loan
  {
    id: 'SOL-029',
    category: 'flash-loan',
    severity: 'critical',
    title: 'Oracle Spot Price Manipulation via Flash Loan',
    protocol: 'Lending Protocol',
    platform: 'Immunefi',
    description: 'Protocol uses AMM spot price as oracle, manipulable within single transaction.',
    impact: 'Attacker borrows at manipulated price, extracts protocol funds.',
    code: `function getPrice() external view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    return r1 * 1e18 / r0;  // Spot price!
}`,
    fix: `// Use Chainlink or TWAP with sufficient period
function getPrice() external view returns (uint256) {
    return chainlink.latestAnswer();
}`,
  },
  {
    id: 'SOL-030',
    category: 'flash-loan',
    severity: 'high',
    title: 'VeToken Voting Power via Flash Loan',
    protocol: 've Governance',
    platform: 'Code4rena',
    description: 'veToken checkpoint allows immediate voting power increase from deposits.',
    impact: 'Flash loan tokens, gain voting power, pass proposal, return tokens.',
    code: `function checkpoint() external {
    // Voting power based on current balance
    votingPower[msg.sender] = token.balanceOf(msg.sender);
}`,
    fix: `// Use time-weighted voting power
// Or snapshot at proposal creation block`,
  },
  
  // More Arithmetic  
  {
    id: 'SOL-031',
    category: 'arithmetic',
    severity: 'high',
    title: 'Rounding Favors Attacker in Withdrawal',
    protocol: 'Vault Protocol',
    platform: 'Sherlock',
    description: 'Withdrawal rounds up shares burned but rounds down assets returned.',
    impact: 'Attacker extracts extra value via many small withdrawals.',
    code: `function withdraw(uint256 assets) external returns (uint256 shares) {
    shares = assets.mulDiv(totalSupply, totalAssets, Math.Rounding.Up);  // Up
    assets = shares.mulDiv(totalAssets, totalSupply, Math.Rounding.Down);  // Down
}`,
    fix: `// Round in protocol's favor
shares = assets.mulDiv(totalSupply, totalAssets, Math.Rounding.Up);
assets = shares.mulDiv(totalAssets, totalSupply, Math.Rounding.Up);`,
  },
  {
    id: 'SOL-032',
    category: 'arithmetic',
    severity: 'medium',
    title: 'Interest Accrual Skipped for Small Amounts',
    protocol: 'Lending Protocol',
    platform: 'Code4rena',
    description: 'Integer division causes 0 interest for small debt amounts over short periods.',
    impact: 'Small borrowers pay no interest, subsidized by large borrowers.',
    code: `uint256 interest = principal * rate * time / 1e18 / SECONDS_PER_YEAR;
// If principal * rate * time < 1e18 * YEAR, interest = 0`,
    fix: `// Use higher precision internally
// Or minimum interest amount`,
  },
  {
    id: 'SOL-033',
    category: 'arithmetic',
    severity: 'critical',
    title: 'Unchecked uint256 to int256 Cast',
    protocol: 'Perp DEX',
    platform: 'Sherlock',
    description: 'Large positive uint256 becomes negative when cast to int256.',
    impact: 'Position values become negative, enabling exploitation.',
    code: `int256 pnl = int256(positionValue - initialValue);
// If positionValue > type(int256).max, pnl is negative!`,
    fix: `require(positionValue <= uint256(type(int256).max), "Overflow");
int256 pnl = int256(positionValue) - int256(initialValue);`,
  },
  
  // More Token
  {
    id: 'SOL-034',
    category: 'token',
    severity: 'high',
    title: 'Rebasing Token Balance Mismatch',
    protocol: 'Vault Protocol',
    platform: 'Code4rena',
    description: 'Protocol caches rebasing token balance, but actual balance changes.',
    impact: 'Accounting mismatch leads to stuck funds or extra withdrawals.',
    code: `mapping(address => uint256) public deposits;
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    deposits[msg.sender] += amount;  // Cached, not actual
}`,
    fix: `// Track shares instead of amounts for rebasing tokens
// Or use wrapper that handles rebasing`,
  },
  {
    id: 'SOL-035',
    category: 'token',
    severity: 'medium',
    title: 'Pausable Token Blocks Liquidations',
    protocol: 'Lending Protocol',
    platform: 'Sherlock',
    description: 'Token transfer pause prevents liquidations, accumulating bad debt.',
    impact: 'Protocol accrues bad debt during pause period.',
    code: `function liquidate(address user) external {
    // If token is paused, this reverts
    collateralToken.transfer(liquidator, collateral);
}`,
    fix: `// Whitelist liquidation function from pause
// Or use pull-pattern for liquidations`,
  },
  {
    id: 'SOL-036',
    category: 'token',
    severity: 'high',
    title: 'ERC777 Callback Reentrancy in Deposit',
    protocol: 'Staking Protocol',
    platform: 'Code4rena',
    description: 'ERC777 tokensReceived callback triggers before deposit state update.',
    impact: 'Attacker can deposit same tokens multiple times.',
    code: `function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);  // Callback here
    balances[msg.sender] += amount;
}`,
    fix: `function deposit(uint256 amount) external nonReentrant {
    balances[msg.sender] += amount;  // State first
    token.transferFrom(msg.sender, address(this), amount);
}`,
  },
  
  // More Signature
  {
    id: 'SOL-037',
    category: 'signature',
    severity: 'high',
    title: 'Missing Nonce in Signature Allows Replay',
    protocol: 'Meta-transaction Protocol',
    platform: 'Immunefi',
    description: 'Signed message lacks nonce, allowing same signature to be used multiple times.',
    impact: 'Attacker replays authorized action multiple times.',
    code: `function executeWithSig(bytes calldata data, bytes calldata sig) external {
    address signer = recover(keccak256(data), sig);
    require(signer == owner, "Invalid signer");
    _execute(data);  // Can be called again with same sig
}`,
    fix: `mapping(uint256 => bool) public usedNonces;
function executeWithSig(uint256 nonce, bytes calldata data, bytes calldata sig) external {
    require(!usedNonces[nonce], "Nonce used");
    usedNonces[nonce] = true;
    // ... verify and execute
}`,
  },
  {
    id: 'SOL-038',
    category: 'signature',
    severity: 'medium',
    title: 'ecrecover Returns Zero for Invalid Signature',
    protocol: 'DeFi Protocol',
    platform: 'Code4rena',
    description: 'ecrecover returns address(0) for invalid signatures instead of reverting.',
    impact: 'If zero address has special permissions, bypass possible.',
    code: `address signer = ecrecover(hash, v, r, s);
require(authorized[signer], "Not authorized");  // Passes if signer = 0`,
    fix: `address signer = ecrecover(hash, v, r, s);
require(signer != address(0), "Invalid signature");
require(authorized[signer], "Not authorized");`,
  },
  
  // More Governance
  {
    id: 'SOL-039',
    category: 'governance',
    severity: 'high',
    title: 'Proposal Spam Denial of Service',
    protocol: 'DAO Protocol',
    platform: 'Sherlock',
    description: 'No limit on active proposals allows attacker to spam and prevent legitimate governance.',
    impact: 'Governance gridlock, unable to pass critical proposals.',
    code: `function propose(bytes calldata data) external returns (uint256) {
    // No limit on proposals
    proposals[nextId++] = Proposal(data, block.timestamp);
}`,
    fix: `require(activeProposals < MAX_ACTIVE_PROPOSALS, "Too many proposals");
require(proposerLastProposal[msg.sender] + COOLDOWN < block.timestamp);`,
  },
  {
    id: 'SOL-040',
    category: 'governance',
    severity: 'critical',
    title: 'Low Quorum Enables Hostile Takeover',
    protocol: 'DAO Protocol',
    platform: 'Code4rena',
    description: 'Quorum set too low relative to circulating supply allows minority takeover.',
    impact: 'Attacker with 5% of tokens can pass any proposal.',
    code: `uint256 public constant QUORUM = 1_000_000e18;  // Fixed amount
// But total supply is 100_000_000e18, quorum is only 1%`,
    fix: `// Use percentage-based quorum
uint256 quorum = totalSupply * QUORUM_PERCENTAGE / 100;`,
  },
  
  // More Upgrade
  {
    id: 'SOL-041',
    category: 'upgrade',
    severity: 'high',
    title: 'Delegatecall to Arbitrary Address',
    protocol: 'Proxy Protocol',
    platform: 'Immunefi',
    description: 'Function allows delegatecall to user-provided address.',
    impact: 'Attacker can execute arbitrary code in proxy context.',
    code: `function multicall(address target, bytes calldata data) external {
    target.delegatecall(data);  // Arbitrary delegatecall!
}`,
    fix: `// Whitelist allowed targets
require(allowedTargets[target], "Target not allowed");`,
  },
  {
    id: 'SOL-042',
    category: 'upgrade',
    severity: 'critical',
    title: 'Implementation Contains selfdestruct',
    protocol: 'Upgradeable Protocol',
    platform: 'Immunefi',
    description: 'Implementation contract has selfdestruct that can be called directly.',
    impact: 'Attacker destroys implementation, bricking all proxies.',
    code: `function destroy() external onlyOwner {
    selfdestruct(payable(owner));
}`,
    fix: `// Never use selfdestruct in implementations
// Or add proxy-only modifier`,
  },
  
  // More DoS
  {
    id: 'SOL-043',
    category: 'dos',
    severity: 'high',
    title: 'External Call in Loop Causes Revert Propagation',
    protocol: 'Distribution Protocol',
    platform: 'Code4rena',
    description: 'One failed transfer in loop reverts entire distribution.',
    impact: 'Single blacklisted address blocks all distributions.',
    code: `function distribute(address[] calldata recipients) external {
    for (uint i = 0; i < recipients.length; i++) {
        token.transfer(recipients[i], amount);  // One failure = all fail
    }
}`,
    fix: `for (uint i = 0; i < recipients.length; i++) {
    try token.transfer(recipients[i], amount) {} 
    catch { failedTransfers.push(recipients[i]); }
}`,
  },
  {
    id: 'SOL-044',
    category: 'dos',
    severity: 'medium',
    title: 'Block Gas Limit Prevents Withdrawal',
    protocol: 'Staking Protocol',
    platform: 'Sherlock',
    description: 'Reward calculation iterates through all epochs since deposit.',
    impact: 'Long-term stakers cannot withdraw due to gas limit.',
    code: `function claimRewards() external {
    for (uint i = depositEpoch[msg.sender]; i < currentEpoch; i++) {
        rewards += calculateEpochReward(msg.sender, i);
    }
}`,
    fix: `// Checkpoint rewards periodically
// Or allow partial claims`,
  },
  
  // More Cross-chain
  {
    id: 'SOL-045',
    category: 'cross-chain',
    severity: 'critical',
    title: 'Missing Chain ID in Cross-chain Message',
    protocol: 'Bridge Protocol',
    platform: 'Immunefi',
    description: 'Bridge message lacks destination chain ID, can be delivered to wrong chain.',
    impact: 'Funds delivered to unintended chain or stolen.',
    code: `bytes32 messageHash = keccak256(abi.encode(
    sender,
    recipient,
    amount
    // Missing: targetChainId
));`,
    fix: `bytes32 messageHash = keccak256(abi.encode(
    sender,
    recipient,
    amount,
    targetChainId,
    nonce
));`,
  },
  {
    id: 'SOL-046',
    category: 'cross-chain',
    severity: 'high',
    title: 'Bridge Finality Assumption Violated',
    protocol: 'Bridge Protocol',
    platform: 'Code4rena',
    description: 'Bridge assumes source chain finality but chain can reorg.',
    impact: 'Double-spend on destination after source chain reorg.',
    code: `// Processes message immediately without waiting for finality
function receiveMessage(bytes calldata message) external {
    _processImmediately(message);
}`,
    fix: `// Wait for sufficient confirmations before processing
require(sourceBlockNumber + FINALITY_BLOCKS <= currentBlock);`,
  },
  
  // More Slippage
  {
    id: 'SOL-047',
    category: 'slippage',
    severity: 'high',
    title: 'deadline = block.timestamp in Swap',
    protocol: 'DEX Aggregator',
    platform: 'Sherlock',
    description: 'Setting deadline to block.timestamp means transaction can be held indefinitely.',
    impact: 'Pending transaction executed at unfavorable future price.',
    code: `router.swapExactTokensForTokens(
    amountIn,
    minOut,
    path,
    recipient,
    block.timestamp  // Always passes!
);`,
    fix: `router.swapExactTokensForTokens(
    amountIn,
    minOut,
    path,
    recipient,
    block.timestamp + 300  // 5 minute deadline
);`,
  },
  {
    id: 'SOL-048',
    category: 'slippage',
    severity: 'medium',
    title: 'Multi-hop Slippage Accumulation',
    protocol: 'DEX Protocol',
    platform: 'Code4rena',
    description: 'Slippage tolerance applied per-hop accumulates across path.',
    impact: 'Longer paths suffer more slippage than expected.',
    code: `// 3-hop path with 1% slippage each = ~3% total
// User expects 1%, loses 3%`,
    fix: `// Apply total slippage budget across entire path
// Or use path-aware slippage calculation`,
  },
  
  // Additional high-value findings
  {
    id: 'SOL-049',
    category: 'oracle',
    severity: 'critical',
    title: 'Curve LP Token Price Manipulation',
    protocol: 'Lending Protocol',
    platform: 'Sherlock',
    description: 'Using get_virtual_price() for Curve LP valuation, manipulable via read-only reentrancy.',
    impact: 'Attacker inflates collateral value during Curve callback.',
    code: `function getLPValue(address pool) external view returns (uint256) {
    return ICurve(pool).get_virtual_price() * lpBalance;
}`,
    fix: `// Check Curve reentrancy lock
// Or use Chainlink LP oracle`,
  },
  {
    id: 'SOL-050',
    category: 'arithmetic',
    severity: 'high',
    title: 'Compound Interest Calculation Error',
    protocol: 'Lending Protocol',
    platform: 'Code4rena',
    description: 'Simple interest formula used instead of compound, diverges over time.',
    impact: 'Borrowers pay less interest than expected, protocol loses.',
    code: `// Simple interest
uint256 interest = principal * rate * time / SECONDS_PER_YEAR;`,
    fix: `// Compound interest with per-block accrual
uint256 ratePerBlock = rate / BLOCKS_PER_YEAR;
uint256 factor = (1 + ratePerBlock) ** blocks;
uint256 amount = principal * factor;`,
  },
];
