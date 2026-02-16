# Known Findings Index (Dedup Baseline)

> 用於最終報告去重。新增 finding 前先查這裡。

## Key Format

`<fingerprint> => <reference>`

fingerprint = `<contract>::<function>::<root-cause-key>`

---

## Entries (30)

### Zaros 2025
1. `Vault::updateVaultAndCreditDelegationWeight::business-logic:weight-allocation:sum-exceeds-100` => `case-study:zaros-2025`
2. `CreditDelegationBranch::settleVaultDebts::business-logic:comparison:sign-inversion` => `case-study:zaros-2025`

### RAAC 2025
3. `LendingPool::getNFTPrice::oracle:staleness:timestamp-unused` => `case-study:raac-2025`
4. `StabilityPool::getExchangeRate::business-logic:hardcoded:return-constant` => `case-study:raac-2025`
5. `NFTLiquidator::placeBid::liquidation:auction:min-first-bid-missing` => `case-study:raac-2025`
6. `NFTLiquidator::buyBackNFT::reentrancy:external-call:guard-missing` => `case-study:raac-2025`

### Revert Lend 2024
7. `V3Vault::deposit::input-validation:permit2-token-unverified` => `case-study:revert-lend-2024`
8. `V3Vault::onERC721Received::reentrancy:erc721-callback` => `case-study:revert-lend-2024`
9. `V3Vault::transform::input-validation:tokenid-unverified` => `case-study:revert-lend-2024`
10. `V3Utils::execute::access-control:missing-auth` => `case-study:revert-lend-2024`
11. `V3Oracle::_getReferenceTokenPriceX96::math:negative-tick-rounding` => `case-study:revert-lend-2024`
12. `V3Vault::liquidate::dos:callback-griefing` => `case-study:revert-lend-2024`
13. `V3Vault::createLoan::limit-bypass:collateral-cap` => `case-study:revert-lend-2024`
14. `V3Vault::borrow::interest:same-block-free-loan` => `case-study:revert-lend-2024`
15. `V3Vault::setReserveFactor::state-update:missing-accrue` => `case-study:revert-lend-2024`

### Wise Lending 2024
16. `WiseLending::receive::reentrancy:guard-reset-via-receive` => `case-study:wise-lending-2024`
17. `WiseLending::paybackExactShares::business-logic:debt-elimination` => `case-study:wise-lending-2024`

### Decent 2024
18. `UTBOwned::setRouter::access-control:missing-onlyOwner` => `case-study:decent-2024`
19. `DecentBridgeExecutor::execute::cross-chain:gas-insufficient` => `case-study:decent-2024`
20. `StargateBridgeAdapter::bridge::cross-chain:refund-encoding-error` => `case-study:decent-2024`
21. `UTB::swapAndExecute::token:weth-fallback-logic` => `case-study:decent-2024`

### THORChain 2024
22. `THORChain_Router::deposit::token:rebasing-token-theft` => `case-study:thorchain-2024`
23. `THORChain_Router::transferOut::access-control:transferout-no-auth` => `case-study:thorchain-2024`

### Size 2024
24. `Size::buyCreditMarket::math:swap-fee-calculation` => `case-study:size-2024`
25. `Size::sellCreditMarket::business-logic:fragmentation-attack` => `case-study:size-2024`
26. `Size::liquidate::liquidation:overcollateralized-liquidation` => `case-study:size-2024`
27. `Size::buyCreditMarket::business-logic:rate-manipulation` => `case-study:size-2024`

### Sentiment v2 2024
28. `RiskEngine::isPositionHealthy::business-logic:multi-collateral-ratio` => `case-study:sentiment-v2-2024`

### EigenLayer 2024 (NEW)
29. `DelegationManager::completeQueuedWithdrawal::withdrawal-delay:operator-change-bypass` => `case-study:eigenlayer-2024`

### ERC-4337 AA 2024 (NEW)
30. `VerifyingPaymaster::validatePaymasterUserOp::paymaster:deposit-drain` => `case-study:erc4337-aa-2024`

---

## Dedup Rule

若新發現與既有條目同 fingerprint：
1. 標記 `duplicate_of`
2. 不重複列為新漏洞
3. 若證據更強，更新 reference 附註（不要新建重複條目）
