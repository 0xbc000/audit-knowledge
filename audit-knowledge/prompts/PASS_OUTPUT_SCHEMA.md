# PASS Output Schema (Canonical)

> 目的：讓多個 pass / sub-agents 的輸出可串接、可去重、可回放。

## Required Markdown Structure

```markdown
## Pass X Output

### Scope
- contracts: [...]
- functions: [...]
- assumptions: [...]

### Summary
- 一句話總結

### Findings
#### [ID] Title
- severity: Critical|High|Medium|Low|Info
- confidence: High|Medium|Low
- location: file:line (or function signature)
- root_cause: one-line root cause
- impact: one-line impact
- exploit_path:
  1) ...
  2) ...
- evidence:
  - code snippet / numeric proof / invariant breach
- duplicate_check:
  - duplicate_of: <id or none>
  - compared_with: [v12, slither, case-study:xxx]
- fix_hint: one practical fix

### Evidence
- 測試/數字驗證/推導過程

### Dedup Refs
- fingerprint list:
  - <contract>::<function>::<root-cause-key>

### For Next Pass
- next_actions:
  - ...
- open_questions:
  - ...
```

## ID Naming

- Pass 1~6: `P{pass}-{index}`，如 `P2-03`
- Deep dive sub-agent: `DD-{track}-{index}`，如 `DD-BL-01`

## Root Cause Key (for dedup)

建議格式：

`{domain}:{primitive}:{failure}`

例子：
- `business-logic:weight-allocation:sum-exceeds-100`
- `oracle:staleness:timestamp-unused`
- `liquidation:auction:min-first-bid-missing`

## Severity Rule (quick)

- Critical: 可直接造成協議資金大規模損失或永久凍結
- High: 明顯可利用且有實質資金風險
- Medium: 需條件配合但可造成錯誤結算/損失
- Low: 安全邊界弱化、維護性風險
- Info: 設計與實作偏差，但尚無直接 exploit
