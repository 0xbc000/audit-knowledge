# 🔐 Smart Contract Audit Knowledge Base

智能合約審計知識庫（以 **8-Pass** 為唯一標準流程）。

## Canonical Documents

- Master index: [`_index.md`](./_index.md)
- Workflow: [`prompts/WORKFLOW.md`](./prompts/WORKFLOW.md)
- Pass output schema: [`prompts/PASS_OUTPUT_SCHEMA.md`](./prompts/PASS_OUTPUT_SCHEMA.md)
- Dedup index: [`dedup/known-findings-index.md`](./dedup/known-findings-index.md)

## Structure

```
audit-knowledge/
├── vulnerability-patterns/   # 52 個漏洞模式
├── protocol-patterns/        # 9 個協議不變量
├── case-studies/             # 13 個真實案例
├── anti-patterns/            # 10 個高頻 root-cause + 檢查步驟 ⭐NEW
├── benchmark/                # Recall/Precision 基準測試 ⭐NEW
│   ├── ground-truth.json     # 8 案例, 30 findings
│   ├── run-benchmark.sh      # 執行入口
│   └── score.mjs             # 評分（R/P/F1/Dup）
├── prompts/
├── checklists/
├── dedup/
├── source-code/
└── tools/
```

## Current Stats (2026-02-14)

| 類別 | 數量 |
|------|------|
| 漏洞模式 (`*.md`) | 52 |
| 協議不變量 (`invariants.md`) | 9 |
| 案例研究 (`case-studies/*/README.md`) | 16 |
| 原始碼專案 (`source-code/*`) | 11 |

## 8-Pass Flow (Canonical)

- Pass 0 (optional): tool/bootstrap
- Pass 1: protocol analysis
- Pass 2: protocol-specific scan
- Pass 3: universal scan
- Pass 4: historical case-study compare
- Pass 5: business-logic analysis
- Pass 6: report synthesis (draft)
- Pass 7: deep-dive analysis
- Pass 8: final consolidation + dedup

## Usage

### 審計前
1. 判斷協議類型（讀 `protocol-patterns/*`）
2. 載入對應 invariants + checklist
3. 確認輸出格式（`PASS_OUTPUT_SCHEMA.md`）

### 審計中
1. 按 8-pass 流程走
2. 每個 pass 產出結構化輸出
3. Pass 8 前執行 dedup gate

### 審計後
1. 把新模式加入 `vulnerability-patterns/`
2. 把新案例加入 `case-studies/`
3. 把可重用 root-cause 加入 dedup index

---

> 若更新內容，請同步更新 `_index.md` 與本文件統計區塊。
