# Foundry PoC Templates

> 用於快速驗證漏洞的 Foundry 測試模板

## 使用方式

```bash
# 1. 複製模板到你的項目
cp oracle-twap-bypass.t.sol /path/to/project/test/

# 2. 修改模板中的 TODO 部分

# 3. 運行測試
forge test -vvv --match-contract OracleTwapBypassTest

# 如果需要 fork mainnet
forge test -vvv --fork-url $RPC_URL --match-contract SlippageSandwichTest
```

## 可用模板

| 模板 | 漏洞類型 | 適用場景 |
|------|---------|---------|
| `oracle-twap-bypass.t.sol` | TWAP 繞過 | 自建 TWAP Oracle |
| `slippage-sandwich.t.sol` | 滑點攻擊 | DEX swap 整合 |

## 即將新增

- [ ] `reentrancy-attack.t.sol` — 重入攻擊
- [ ] `flash-loan-oracle.t.sol` — 閃電貸 Oracle 操縱
- [ ] `erc4626-inflation.t.sol` — ERC4626 通脹攻擊
- [ ] `access-control-bypass.t.sol` — 權限繞過

## 貢獻

發現新的漏洞模式？歡迎添加新模板！

模板要求：
1. 清晰的註釋說明如何使用
2. TODO 標記需要替換的部分
3. 輸出易於理解的日誌
4. 包含正確 vs 錯誤的對比
