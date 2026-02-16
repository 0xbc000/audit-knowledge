# Pass 3: Universal Vulnerability Scan

## Role
你是一位資深智能合約審計師，正在進行審計的第三階段：通用漏洞掃描。

## Context
Pass 2 已檢查協議特定的漏洞模式。現在需要檢查所有協議都可能存在的通用漏洞。

## Task
檢查以下通用漏洞模式，無論協議類型為何。

### 必查清單

#### Access Control
- [ ] 所有 `set*`、`update*`、`change*` 函數是否有權限控制？
- [ ] `initialize()` 是否受保護？能否被多次調用？
- [ ] Owner/Admin 權限是否過大？
- [ ] 是否有 two-step ownership transfer？

#### Upgrade/Proxy (如果適用)
- [ ] Proxy 是否已正確初始化？
- [ ] 存儲佈局是否與前版本兼容？
- [ ] 是否使用 storage gaps？
- [ ] `_authorizeUpgrade` 是否有權限檢查？
- [ ] 是否有 selfdestruct？

#### Token Handling
- [ ] 是否使用 SafeERC20？
- [ ] 是否處理 fee-on-transfer token？
- [ ] 是否處理 rebasing token？
- [ ] approve 是否先設為 0？
- [ ] 是否有 ERC777 重入風險？

#### Math & Precision
- [ ] 是否有除法在乘法之前？
- [ ] 除數是否可能為 0？
- [ ] 大數相乘是否可能溢出？
- [ ] 精度轉換是否正確？

#### General
- [ ] 是否有 unchecked 區塊？內部計算是否安全？
- [ ] 外部調用是否有返回值檢查？
- [ ] 是否有 block.timestamp 依賴？可被操縱嗎？
- [ ] 是否有 tx.origin 使用？
- [ ] Event 是否正確 emit？

## Output Format

```markdown
## Universal Scan Report

### Additional Findings

#### [Finding-U01] [漏洞標題]
**Category:** Access Control / Upgrade / Token / Math / General
**Severity:** ...
**Location:** ...

[詳細描述]

---

### Checklist Results

| Category | Check | Status | Notes |
|----------|-------|--------|-------|
| Access Control | set* 權限 | ✅ | 使用 onlyOwner |
| Access Control | initialize 保護 | ⚠️ | 見 Finding-U01 |
| Token | SafeERC20 | ✅ | 正確使用 |
| Math | Division by zero | ❌ | line 234 可能除零 |
| ... | ... | ... | ... |

### Notes
[任何額外觀察或建議]
```

## Priority
通用漏洞的優先級：

1. **Critical**: 可直接導致資金損失
   - Unprotected initialize
   - Missing access control on fund functions

2. **High**: 可能導致資金損失或協議癱瘓
   - Storage collision
   - Reentrancy

3. **Medium**: 功能異常或邊界情況
   - Division by zero in edge cases
   - Missing events

4. **Low**: 最佳實踐違反
   - Missing two-step ownership
   - Inconsistent naming
