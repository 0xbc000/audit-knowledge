# Smart Contract Audit Agent Workflow (Canonical)

## Overview

採用 **8-Pass** 流程（Pass 0 可選）。

- Pass 0: Tool bootstrap (optional)
- Pass 1: Protocol Analysis
- Pass 2: Protocol-Specific Scan
- Pass 3: Universal Scan
- Pass 4: Historical Case Study Compare
- Pass 5: Business Logic Analysis
- Pass 6: Report Synthesis (draft)
- Pass 7: Deep Dive Analysis (parallel sub-agents)
- Pass 8: Final Consolidation (dedup + rank + final report)

> 所有 pass 輸出都必須符合 `PASS_OUTPUT_SCHEMA.md`。

---

## Pass-by-Pass

### Pass 0 (Optional)
- 啟動外部工具（如 Solodit MCP）
- 預先載入關鍵索引（protocol / patterns / dedup）

### Pass 1
- 識別協議類型
- 抽取核心不變量與高風險區域

### Pass 2
- 載入協議特定漏洞模式（relevant categories only）
- 產出 confirmed / potential findings

### Pass 3
- 掃描通用漏洞（其餘 categories）

### Pass 4
- 對照歷史案例
- 尋找同根因與可遷移攻擊路徑

### Pass 5
- 數字驗證
- 不變量對抗
- 經濟攻擊視角

### Pass 6
- 產出初步報告（含 PoC / fix hints）

### Pass 7
- 啟動 2~3 個 sub-agents 並行深挖：
  - BL/Economic
  - Cross-contract consistency
  - Protocol-specific track
- 每條 finding 必須有可驗證證據

### Pass 8
- 與 V12/Slither/歷史案例/known-index 去重
- 合併、排序、輸出最終報告

---

## Dedup Gate (Mandatory Before Final)

最終輸出前必做：
1. 比對 `dedup/known-findings-index.md`
2. 比對自動化工具結果
3. 對同 fingerprint 條目標記 `duplicate_of`

Fingerprint format:

`<contract>::<function>::<root-cause-key>`

---

## Output Contract

格式與欄位詳見：
- `prompts/PASS_OUTPUT_SCHEMA.md`
