#!/usr/bin/env node
/**
 * Simple heuristic-based audit scanner for benchmark baseline.
 * Scans Solidity source code for known vulnerability patterns and outputs findings JSON.
 * 
 * Usage: node simple-scanner.mjs <source-dir> <protocol-type>
 * Output: JSON to stdout with { findings: [...] }
 */
import { readdirSync, readFileSync, statSync } from 'fs';
import { join, extname } from 'path';

const sourceDir = process.argv[2];
const protoType = process.argv[3] || 'unknown';

if (!sourceDir) {
  console.error('Usage: node simple-scanner.mjs <source-dir> <protocol-type>');
  process.exit(1);
}

// Collect all .sol files recursively
function collectSolFiles(dir) {
  const results = [];
  try {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      try {
        const st = statSync(full);
        if (st.isDirectory() && !entry.startsWith('.') && entry !== 'node_modules' && entry !== 'lib') {
          results.push(...collectSolFiles(full));
        } else if (st.isFile() && extname(entry) === '.sol') {
          results.push(full);
        }
      } catch {}
    }
  } catch {}
  return results;
}

const files = collectSolFiles(sourceDir);
const findings = [];
let findingId = 1;

// Pattern matchers
const patterns = [
  {
    id: 'access-control:missing-auth',
    title: 'Missing access control on sensitive function',
    severity: 'high',
    test: (content, filename) => {
      // Look for external functions that modify state without onlyOwner/onlyRole/require(msg.sender
      const lines = content.split('\n');
      const matches = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/function\s+\w+.*\bexternal\b/.test(line) && 
            /\b(set|update|withdraw|transfer|pause|unpause|kill|destroy|selfdestruct)\w*/i.test(line) &&
            !/onlyOwner|onlyRole|onlyAdmin|require\s*\(\s*msg\.sender|_checkOwner|modifier/.test(lines.slice(Math.max(0,i-2), i+5).join(' '))) {
          matches.push({ line: i+1, text: line.trim() });
        }
      }
      return matches;
    }
  },
  {
    id: 'reentrancy:external-call-no-guard',
    title: 'External call without reentrancy guard',
    severity: 'high',
    test: (content, filename) => {
      const matches = [];
      if (/ReentrancyGuard/.test(content)) return matches; // Has guard
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/\.call\{value|\.transfer\(|\.send\(/.test(lines[i]) && 
            !/nonReentrant/.test(content.slice(Math.max(0, content.lastIndexOf('function', content.indexOf(lines[i]))), content.indexOf(lines[i])))) {
          matches.push({ line: i+1, text: lines[i].trim() });
        }
      }
      return matches.length > 2 ? matches.slice(0, 3) : matches; // cap
    }
  },
  {
    id: 'oracle:staleness-unchecked',
    title: 'Oracle price staleness not checked',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/latestRoundData|getLatestPrice|getPrice/.test(content)) {
        // Check if timestamp/updatedAt is compared to block.timestamp
        if (!/block\.timestamp\s*-\s*(updatedAt|lastUpdate|timestamp)|MAX_STALENESS|STALENESS/.test(content)) {
          matches.push({ line: 0, text: 'Oracle call without staleness check' });
        }
      }
      return matches;
    }
  },
  {
    id: 'reentrancy:erc721-callback',
    title: 'ERC721 callback reentrancy risk',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/safeTransferFrom|safeMint|_safeMint/.test(content) && !/nonReentrant/.test(content)) {
        matches.push({ line: 0, text: 'safeTransferFrom/safeMint without nonReentrant' });
      }
      if (/onERC721Received/.test(content)) {
        matches.push({ line: 0, text: 'onERC721Received callback present' });
      }
      return matches;
    }
  },
  {
    id: 'input-validation:permit2-token-unverified',
    title: 'Permit2 token address not verified',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/permit2|IPermit2|PERMIT2/.test(content) && !/token\s*==|require.*token|_verifyToken/.test(content)) {
        matches.push({ line: 0, text: 'Permit2 integration without token verification' });
      }
      return matches;
    }
  },
  {
    id: 'math:negative-tick-rounding',
    title: 'Negative tick/value rounding error',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/tick|TWAP|twap/.test(content) && /\//.test(content)) {
        if (/int\d+.*\//.test(content) && !/roundDown|Math\.ceil/.test(content)) {
          matches.push({ line: 0, text: 'Integer division with potential negative rounding issue' });
        }
      }
      return matches;
    }
  },
  {
    id: 'dos:callback-griefing',
    title: 'Callback-based DoS / griefing',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/liquidat/i.test(content) && /safeTransferFrom|\.call\{value/.test(content)) {
        matches.push({ line: 0, text: 'Liquidation with external callback (griefing risk)' });
      }
      return matches;
    }
  },
  {
    id: 'token:rebasing-token-theft',
    title: 'Rebasing/fee-on-transfer token not handled',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/transferFrom.*amount|safeTransferFrom.*amount/.test(content) && 
          !/balanceOf.*before|balanceBefore|_balance/.test(content) &&
          /deposit|vault/i.test(content)) {
        matches.push({ line: 0, text: 'Token transfer without balance-before-after check' });
      }
      return matches;
    }
  },
  {
    id: 'cross-chain:gas-insufficient',
    title: 'Cross-chain gas parameter user-controlled',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/LayerZero|lzSend|_lzSend|ILayerZeroEndpoint/.test(content) && /dstGas|gasForCall/.test(content)) {
        if (!/MIN_GAS|minGas|require.*gas/.test(content)) {
          matches.push({ line: 0, text: 'LayerZero gas parameter without minimum enforcement' });
        }
      }
      return matches;
    }
  },
  {
    id: 'cross-chain:refund-encoding-error',
    title: 'Cross-chain address encoding issue',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/abi\.encodePacked.*address|bytes20.*address/.test(content) && /bridge|cross.*chain|stargate/i.test(content)) {
        matches.push({ line: 0, text: 'Address encoding in cross-chain context' });
      }
      return matches;
    }
  },
  {
    id: 'business-logic:hardcoded-return',
    title: 'Hardcoded return value in critical function',
    severity: 'high',
    test: (content) => {
      const matches = [];
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/function\s+(get|calculate)\w+.*view/.test(lines[i])) {
          // Look ahead for simple return constant
          for (let j = i+1; j < Math.min(i+10, lines.length); j++) {
            if (/return\s+\d+|return\s+1e18|return\s+10\*\*18/.test(lines[j]) && 
                lines.slice(i, j).join('').split('{').length <= 2) {
              matches.push({ line: j+1, text: lines[j].trim() });
            }
          }
        }
      }
      return matches;
    }
  },
  {
    id: 'interest:same-block-free-loan',
    title: 'Same-block borrow/repay yields zero interest',
    severity: 'medium',
    test: (content) => {
      const matches = [];
      if (/borrow|lend/i.test(content) && /block\.timestamp|block\.number/.test(content)) {
        if (!/lastAccrual.*!=.*block|lastUpdate.*!=.*block/.test(content)) {
          matches.push({ line: 0, text: 'Interest calculation may allow same-block free loans' });
        }
      }
      return matches;
    }
  },
  {
    id: 'token:weth-fallback-logic',
    title: 'WETH unwrap/fallback logic error',
    severity: 'high',
    test: (content) => {
      const matches = [];
      if (/WETH|weth|WrappedEther/.test(content) && /withdraw|unwrap/.test(content)) {
        if (/fallback|receive.*payable/.test(content)) {
          matches.push({ line: 0, text: 'WETH unwrap with fallback handling' });
        }
      }
      return matches;
    }
  }
];

for (const filePath of files) {
  let content;
  try { content = readFileSync(filePath, 'utf8'); } catch { continue; }
  const filename = filePath.replace(sourceDir, '').replace(/^\//, '');
  
  for (const pattern of patterns) {
    const matches = pattern.test(content, filename);
    if (matches.length > 0) {
      findings.push({
        id: `F-${String(findingId++).padStart(2, '0')}`,
        severity: pattern.severity,
        root_cause: pattern.id,
        title: pattern.title,
        contract: filename,
        function: matches[0]?.text?.slice(0, 80) || 'N/A',
        matches: matches.length
      });
    }
  }
}

// Deduplicate by root_cause (keep first match)
const seen = new Set();
const deduped = [];
for (const f of findings) {
  if (!seen.has(f.root_cause)) {
    seen.add(f.root_cause);
    deduped.push(f);
  }
}

console.log(JSON.stringify({ findings: deduped }, null, 2));
