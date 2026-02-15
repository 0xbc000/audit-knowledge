# Benchmark Harness

## 指標定義

| 指標 | 公式 | 意義 |
|------|------|------|
| **Recall** | matched / expected | 找到多少已知漏洞 |
| **Precision** | matched / unique_reported | 報告的有多少是真的 |
| **F1** | 2·P·R / (P+R) | 綜合分數 |
| **Duplicate Ratio** | duplicates / total_reported | 重複噪音比例 |

## 檔案結構

```
benchmark/
├── README.md              ← 你在這裡
├── ground-truth.json      ← 8 案例, 30 findings (固定基準)
├── run-benchmark.sh       ← 執行入口
├── score.mjs              ← 評分邏輯
└── results/               ← 每次跑的結果
    └── YYYYMMDD-HHMMSS/
        ├── summary.txt
        └── <case-id>/
            ├── expected.json
            ├── audit-output.json
            └── scorecard.json
```

## 執行方式

```bash
# 跑全部案例
cd /Users/billyc/clawd/audit-knowledge/benchmark
chmod +x run-benchmark.sh
./run-benchmark.sh

# 跑單一案例
./run-benchmark.sh revert-lend-2024

# 只重新評分（不重跑審計）
./run-benchmark.sh --score-only
```

## 整合審計 Agent

在 `run-benchmark.sh` 中找到 `PLACEHOLDER` 區塊，替換為你的 agent 呼叫。
Agent 需要輸出 JSON：

```json
{
  "findings": [
    {
      "id": "F-01",
      "severity": "high",
      "root_cause": "access-control:missing-auth",
      "title": "...",
      "contract": "...",
      "function": "..."
    }
  ]
}
```

## Root Cause 匹配規則

- 完全匹配 或 prefix 匹配（`reentrancy` 匹配 `reentrancy:guard-reset`）
- 同 category 下 token overlap > 50% 也算匹配
- 一對一匹配（不重複計算）

## 當前基準

8 cases, 30 ground-truth findings：
- revert-lend-2024: 11 (6H + 5M)
- zaros-2025: 2 (1C + 1H)
- raac-2025: 4 (2H + 2M)
- wise-lending-2024: 2 (2H)
- decent-2024: 4 (4H)
- thorchain-2024: 2 (2H)
- size-2024: 4 (4H)
- sentiment-v2-2024: 1 (1H)
