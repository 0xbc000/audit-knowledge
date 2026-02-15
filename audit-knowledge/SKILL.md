# Smart Contract Audit Agent

> 系統化智能合約審計 - 8 Pass 流程 (含深度分析)

## 觸發條件

當用戶說：
- "audit this contract"
- "審計這個合約"
- "security review"
- "@audit [path]"

## 快速開始

```
用戶: audit zaros-audit/src/
Agent: 開始 8-Pass 審計流程...
```

## 流程

### Pass 1: Protocol Analysis (5 min)
```
載入: protocol-patterns/_index.md
輸出: 協議類型、核心不變量、高風險區域
```

### Pass 2: Protocol-Specific Scan (15 min)
```
載入: vulnerability-patterns/{相關類型}/*
輸出: 協議特定漏洞
```

### Pass 3: Universal Scan (10 min)
```
載入: vulnerability-patterns/{剩餘}/*
輸出: 通用漏洞
```

### Pass 4: Case Study Compare (10 min)
```
載入: case-studies/{相關}/*
輸出: 歷史對照發現
```

### Pass 5: Business Logic (20 min)
```
載入: checklists/business-logic-checklist.md
方法:
1. 數字驗證 - 用具體數字跑一遍
2. 不變量 - 找必須為真的條件
3. 攻擊者視角 - 成本/收益分析
輸出: 業務邏輯漏洞
```

### Pass 6: Report Synthesis (10 min)
```
載入: prompts/06-report-synthesis.md
輸出: 初步審計報告
```

### Pass 7: Deep Dive Analysis ⭐⭐⭐ 最重要！ (30-60 min)
```
載入: prompts/07-deep-dive-analysis.md
方法:
1. 啟動專門的 sub-agents (並行)
   - 業務邏輯 + 經濟攻擊
   - 跨合約交互分析
   - 協議特定深挖
2. 質量 > 數量 (找真的 High，不是填充 Low)
3. 與已知問題 (V12/之前審計) 去重
輸出: 深度分析發現
```

### Pass 8: Final Report Consolidation (10 min)
```
整合: Pass 6 初步報告 + Pass 7 深挖發現
去重、驗證、排序
輸出: 最終審計報告
```

## 使用方式

### 完整審計
```
audit [path] --full
```

### 快速掃描 (Pass 1-3 only)
```
audit [path] --quick
```

### 指定 Pass
```
audit [path] --pass 5
```

## 資源路徑

```
audit-knowledge/
├── prompts/           # 每個 Pass 的詳細指令
├── vulnerability-patterns/  # 84+ 漏洞模式
├── case-studies/      # 歷史案例
├── protocol-patterns/ # 協議類型識別
└── checklists/        # 快速檢查表
```

## 輸出格式

最終報告包含：
- Executive Summary
- Findings by Severity (C/H/M/L/Info)
- 每個 Finding 有 PoC + Fix
- Methodology 說明

## 注意事項

1. **Token 消耗大** - 完整審計可能用 100K+ tokens
2. **時間預估** - 完整流程約 1 小時
3. **最佳實踐** - 先跑 --quick，確認方向後再 --full
