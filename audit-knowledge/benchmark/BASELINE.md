# Benchmark Baseline — 2026-02-15

> Heuristic scanner (simple-scanner.mjs) 首次全量執行結果

## 聚合指標

| 指標 | 值 | 說明 |
|------|-----|------|
| **Recall** | 38.3% | 24 個已知漏洞中找到 11 個 |
| **Precision** | 27.8% | 報告的 findings 中真陽性佔比 |
| **F1** | 30.6% | 調和平均 |
| **Duplicate Ratio** | 0.0% | 無重複報告 |
| **Cases Scored** | 6/8 | 2 cases 因 source code 缺失跳過 (zaros, raac) |

## 各案例 Scorecard

| Case | Protocol | Expected | Found | TP | FP | Recall | Precision | F1 |
|------|----------|----------|-------|----|----|--------|-----------|-----|
| revert-lend-2024 | lending | 11 | 9 | 6 | 3 | 54.5% | 66.7% | 60.0% |
| decent-2024 | bridge | 4 | 5 | 3 | 2 | 75.0% | 60.0% | 66.7% |
| thorchain-2024 | bridge | 2 | 5 | 2 | 3 | 100% | 40.0% | 57.1% |
| wise-lending-2024 | lending | 2 | 8 | 0 | 8 | 0% | 0% | 0% |
| size-2024 | lending | 4 | 7 | 0 | 7 | 0% | 0% | 0% |
| sentiment-v2-2024 | lending | 1 | 7 | 0 | 7 | 0% | 0% | 0% |

## 解讀

### 強項
- **Cross-chain bridge** 案例表現最佳（Recall 75-100%），因為跨鏈漏洞模式（missing auth、gas griefing、address encoding）可被 grep pattern 有效偵測
- **Revert Lend** 找到 6/11（54.5%），因漏洞類型多樣（permit2、reentrancy、callback griefing）且 pattern matching 有效

### 弱項
- **Wise Lending** 0/2 — 核心漏洞是 `receive()` 重置 reentrancy guard，此為語義級漏洞，heuristic scanner 無法捕捉
- **Size / Sentiment** 0/4、0/1 — 漏洞為 business logic（swap fee 計算、碎片化攻擊、multi-collateral ratio），需語義理解
- **高 FP 率** — scanner 過於激進地報告 potential issues，需要 LLM 進行語義過濾

### 根因分析
| 漏洞類型 | 可偵測 | 不可偵測 |
|----------|--------|----------|
| Missing access control | ✅ | |
| Callback reentrancy | ✅ | |
| Oracle staleness | ✅ | |
| Cross-chain gas/encoding | ✅ | |
| Business logic errors | | ❌ |
| Math calculation bugs | | ❌ |
| Guard reset via receive() | | ❌ |
| Rate manipulation | | ❌ |

### 結論
Heuristic scanner 作為 baseline 有意義：
1. 為 pattern-matchable 漏洞提供 ~60% recall
2. 完全無法偵測 business logic / semantic 漏洞
3. LLM-based agent 的目標應 ≥ 70% Recall、≥ 50% Precision

## 執行指令

```bash
# 重現此 baseline
cd audit-knowledge
bash benchmark/run-benchmark.sh

# 只重新評分（不重跑 scanner）
bash benchmark/run-benchmark.sh --score-only
```

## 缺失案例
- `zaros-2025`: source code dir `source-code/zaros-part-1` 不存在
- `raac-2025`: source code dir `source-code/2025-01-pieces-of-a-puzzle` 不存在

需要下載/symlink 這兩個 repo 才能完成全量 benchmark。
