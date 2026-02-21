# Audit Knowledge Base - Master Index

## 🚀 Quick Start

```bash
# 完整審計（建議）
"audit [path] --full"

# 快速掃描（Pass 1-3）
"audit [path] --quick"
```

**Canonical flow:** 8-Pass（Pass 0 為可選工具啟動）  
**Agent:** [SKILL.md](SKILL.md) | [agent/audit-agent.md](agent/audit-agent.md)

---

## 知識庫結構

```
audit-knowledge/
├── vulnerability-patterns/   # 漏洞模式
├── protocol-patterns/        # 協議類型不變量
├── case-studies/             # 真實審計案例
├── prompts/                  # 8-Pass 審計流程
├── checklists/               # 快速檢查表
├── dedup/                    # 已知問題索引與去重規則
└── agent/                    # Agent 配置
```

## Current Stats (2026-02-22)

- Vulnerability patterns: **64** (+8 liquidation patterns)
- Protocol invariant sets: **9**
- Case studies: **13**
- Source-code repos: **11**

> 若新增內容，請同步更新本段與 `README.md`。

---

## Canonical Audit Flow (8-Pass)

- Pass 0（optional）: 啟動工具 / context preload
- Pass 1: Protocol Analysis
- Pass 2: Protocol-Specific Vulnerability Scan
- Pass 3: Universal Vulnerability Scan
- Pass 4: Historical Case Study Comparison
- Pass 5: Business Logic Analysis
- Pass 6: Report Synthesis (draft)
- Pass 7: Deep Dive Analysis（sub-agents 並行）
- Pass 8: Final Consolidation（去重 + 排序 + 最終報告）

詳見：[`prompts/WORKFLOW.md`](prompts/WORKFLOW.md)

---

## Output Contract（必遵守）

每個 pass 輸出都要符合：
- [`prompts/PASS_OUTPUT_SCHEMA.md`](prompts/PASS_OUTPUT_SCHEMA.md)

最少欄位：
- scope
- findings
- evidence
- dedup_refs
- next_actions

---

## 去重規則

提交最終報告前，必須比對：
1. 自動化工具結果（V12/Slither/4naly3er）
2. 既有 case studies
3. [`dedup/known-findings-index.md`](dedup/known-findings-index.md)

若命中同根因，標記 `duplicate_of`，不要重複算新發現。
