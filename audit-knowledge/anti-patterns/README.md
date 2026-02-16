# Anti-Pattern Database

高頻 root-cause 對應檢查步驟和測試腳本。每個 anti-pattern 是一個可執行的檢查單元。

## 使用方式

審計時根據協議類型，載入相關 anti-pattern，逐一檢查。

## 索引

| ID | Root Cause | 嚴重度 | 協議類型 | 出現次數 |
|----|-----------|--------|---------|---------|
| AP-01 | Access Control: Missing Auth | H/C | All | 3+ |
| AP-02 | Reentrancy: Callback-based | H | Lending/NFT | 3+ |
| AP-03 | Math: Rounding/Precision | H/M | All | 4+ |
| AP-04 | Oracle: Staleness/Manipulation | H | Lending/DEX | 3+ |
| AP-05 | Business Logic: Weight/Sum | C | Vault/DEX | 2+ |
| AP-06 | Input Validation: Unverified Params | H | All | 3+ |
| AP-07 | Cross-Chain: Gas/Encoding | H | Bridge | 2+ |
| AP-08 | Token: Non-standard Behavior | H | All | 3+ |
| AP-09 | Liquidation: Broken Incentives | M/H | Lending | 3+ |
| AP-10 | State Update: Missing Pre-update | M | All | 2+ |
