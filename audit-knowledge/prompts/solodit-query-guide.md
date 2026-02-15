# Solodit 查詢指南

## 概述

Solodit 是一個真實漏洞資料庫，收集了來自 Code4rena、Sherlock、Immunefi 等平台的審計發現。
整合 Solodit 可以讓你：

1. 驗證發現是否為已知漏洞類型
2. 找到類似的歷史案例作為佐證
3. 參考專業審計員的描述和修復建議

---

## 使用方式

### 方式 1: Helper Script (推薦)

```bash
# 啟動 server
./scripts/solodit-helper.sh start

# 搜尋
./scripts/solodit-helper.sh search "reentrancy"

# 取得完整報告
./scripts/solodit-helper.sh get "h-1-vulnerability-slug"
```

### 方式 2: 直接 curl

```bash
# 啟動 server
npx -y @lyuboslavlyubenov/solodit-mcp &

# 搜尋
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"keywords":"YOUR_KEYWORDS"}}}'
```

---

## 查詢策略

### 按代碼模式查詢

| 發現的代碼模式 | 推薦查詢關鍵字 |
|---------------|---------------|
| 使用 Chainlink | `chainlink stale price`, `oracle heartbeat` |
| 使用 Uniswap swap | `slippage amountOutMin`, `sandwich attack` |
| 使用 TWAP | `twap manipulation`, `oracle price` |
| ERC721 transfer | `onERC721Received reentrancy` |
| Flash loan 整合 | `flash loan attack`, `callback reentrancy` |
| Proxy 升級 | `uninitialized proxy`, `storage collision` |
| 跨鏈訊息 | `bridge replay`, `cross chain` |
| ERC4626 vault | `share inflation`, `donation attack` |

### 按協議類型查詢

| 協議類型 | 推薦查詢關鍵字 |
|---------|---------------|
| Lending | `liquidation`, `collateral factor`, `bad debt` |
| DEX/AMM | `slippage`, `swap`, `liquidity provision` |
| Staking | `reward distribution`, `stake withdrawal` |
| Governance | `voting power`, `proposal`, `timelock` |
| Bridge | `message verification`, `nonce replay` |
| NFT | `royalty`, `approval`, `transfer` |

### 按可疑行為查詢

| 可疑行為 | 推薦查詢關鍵字 |
|---------|---------------|
| 外部調用後更新狀態 | `reentrancy`, `callback` |
| 未驗證返回值 | `return value`, `unchecked` |
| 除法在乘法前 | `precision loss`, `rounding` |
| 硬編碼參數 | `hardcoded`, `magic number` |
| 無訪問控制 | `access control`, `unauthorized` |

---

## 如何利用搜尋結果

### 步驟 1: 搜尋相關關鍵字
```bash
./scripts/solodit-helper.sh search "oracle twap"
```

### 步驟 2: 獲取相關報告詳情
從搜尋結果中選擇最相關的 slug：
```bash
./scripts/solodit-helper.sh get "h-1-twap-manipulation-xxx"
```

### 步驟 3: 對比代碼
- 閱讀 Solodit 報告中的漏洞描述
- 對比目標代碼是否有相同模式
- 注意修復建議

### 步驟 4: 在報告中引用
如果確認漏洞相似，在你的審計報告中引用：

```markdown
### [H-01] TWAP Oracle 可被操縱

**Description:** ...

**Solodit Similar Cases:**
- [H-1: TWAP manipulation in XYZ Protocol](solodit-link)
  - 相似度: 90%
  - 核心問題相同: 使用單一區塊的累積價格

**Fix:** 參考 Solodit 案例中的修復方案...
```

---

## 最佳實踐

### ✅ DO

1. **先搜尋後分析** — 發現可疑代碼時先查 Solodit 是否有類似案例
2. **多關鍵字組合** — 嘗試不同組合以獲得更精確的結果
3. **閱讀完整報告** — 不只看標題，要看漏洞細節和修復
4. **引用增加可信度** — 有 Solodit 佐證的發現更有說服力

### ❌ DON'T

1. **不要只依賴 Solodit** — 它是補充，不能取代手動分析
2. **不要假設相似 = 相同** — 仔細確認漏洞模式是否真的匹配
3. **不要複製貼上** — 根據目標代碼調整描述和影響評估
4. **不要忽略新型漏洞** — Solodit 沒有的不代表不是漏洞

---

## 範例工作流程

```
1. 分析代碼，發現使用 Chainlink oracle
2. 查詢: ./scripts/solodit-helper.sh search "chainlink stale"
3. 發現 10 個相關案例
4. 選擇最相關的 2-3 個，獲取完整報告
5. 對比: 目標代碼是否檢查 updatedAt？
6. 如果沒有 → 確認漏洞，引用 Solodit 案例
7. 如果有 → 檢查 threshold 是否合理
8. 寫入報告，附上 Solodit 參考
```

---

*此文檔是 audit-knowledge 的一部分，與 audit-agent.md 配合使用*
