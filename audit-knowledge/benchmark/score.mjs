#!/usr/bin/env node
/**
 * Benchmark Scorer
 * 
 * Compares audit-output.json against expected.json for each case.
 * Matching logic: root_cause prefix match (e.g., "reentrancy:*" matches "reentrancy:guard-reset-via-receive")
 * 
 * Metrics:
 *   - Recall:          matched / expected  (did we find known vulns?)
 *   - Precision:       matched / reported   (are our findings real?)
 *   - Duplicate Ratio: duplicates / reported (how much noise?)
 *   - F1:              2 * P * R / (P + R)
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'fs';
import { join } from 'path';

const groundTruthPath = process.argv[2];
const resultsDir = process.argv[3];

if (!groundTruthPath || !resultsDir) {
  console.error('Usage: node score.mjs <ground-truth.json> <results-dir>');
  process.exit(1);
}

const groundTruth = JSON.parse(readFileSync(groundTruthPath, 'utf8'));

// Matching: two root_cause strings match if one is a prefix of the other,
// or if they share the same top-level category and have >50% token overlap.
function rootCauseMatch(expected, reported) {
  if (!expected || !reported) return false;
  const e = expected.toLowerCase();
  const r = reported.toLowerCase();
  
  // Exact or prefix
  if (e === r || e.startsWith(r) || r.startsWith(e)) return true;
  
  // Token overlap within same category
  const eParts = e.split(/[:\-_/]/);
  const rParts = r.split(/[:\-_/]/);
  if (eParts[0] !== rParts[0]) return false;
  
  const eSet = new Set(eParts);
  const overlap = rParts.filter(t => eSet.has(t)).length;
  return overlap / Math.max(eParts.length, rParts.length) > 0.5;
}

const allScores = [];

for (const caseEntry of groundTruth.cases) {
  const caseDir = join(resultsDir, caseEntry.id);
  if (!existsSync(caseDir)) continue;
  
  const expectedPath = join(caseDir, 'expected.json');
  const outputPath = join(caseDir, 'audit-output.json');
  
  if (!existsSync(outputPath)) continue;
  
  const expected = JSON.parse(readFileSync(expectedPath, 'utf8'));
  const output = JSON.parse(readFileSync(outputPath, 'utf8'));
  
  if (output.error) {
    console.log(`[${caseEntry.id}] SKIPPED — ${output.error}`);
    continue;
  }
  
  const reported = output.findings || [];
  const matched = new Set();
  const falsePositives = [];
  const duplicates = [];
  const seenRootCauses = new Set();
  
  for (const finding of reported) {
    const rc = finding.root_cause || '';
    
    // Check for duplicate
    if (seenRootCauses.has(rc)) {
      duplicates.push(finding);
      continue;
    }
    seenRootCauses.add(rc);
    
    // Try to match against expected
    let foundMatch = false;
    for (let i = 0; i < expected.length; i++) {
      if (matched.has(i)) continue;
      if (rootCauseMatch(expected[i].root_cause, rc)) {
        matched.add(i);
        foundMatch = true;
        break;
      }
    }
    
    if (!foundMatch) {
      falsePositives.push(finding);
    }
  }
  
  const tp = matched.size;
  const totalExpected = expected.length;
  const totalReported = reported.length;
  const uniqueReported = totalReported - duplicates.length;
  
  const recall = totalExpected > 0 ? tp / totalExpected : 0;
  const precision = uniqueReported > 0 ? tp / uniqueReported : 0;
  const f1 = (precision + recall) > 0 ? 2 * precision * recall / (precision + recall) : 0;
  const dupRatio = totalReported > 0 ? duplicates.length / totalReported : 0;
  
  const scorecard = {
    case_id: caseEntry.id,
    protocol_type: caseEntry.protocol_type,
    expected_count: totalExpected,
    reported_count: totalReported,
    unique_reported: uniqueReported,
    true_positives: tp,
    false_positives: falsePositives.length,
    duplicates: duplicates.length,
    missed: totalExpected - tp,
    recall: Math.round(recall * 1000) / 1000,
    precision: Math.round(precision * 1000) / 1000,
    f1: Math.round(f1 * 1000) / 1000,
    duplicate_ratio: Math.round(dupRatio * 1000) / 1000,
    missed_findings: expected.filter((_, i) => !matched.has(i)).map(f => f.id + ': ' + f.title),
    false_positive_list: falsePositives.map(f => f.title || f.id || 'unknown')
  };
  
  writeFileSync(join(caseDir, 'scorecard.json'), JSON.stringify(scorecard, null, 2));
  allScores.push(scorecard);
  
  console.log(`[${caseEntry.id}] R=${scorecard.recall} P=${scorecard.precision} F1=${scorecard.f1} Dup=${scorecard.duplicate_ratio} (${tp}/${totalExpected} found, ${falsePositives.length} FP, ${duplicates.length} dup)`);
}

// Aggregate
if (allScores.length > 0) {
  const avg = (key) => allScores.reduce((s, c) => s + c[key], 0) / allScores.length;
  console.log('');
  console.log('=== AGGREGATE ===');
  console.log(`Cases:     ${allScores.length}`);
  console.log(`Recall:    ${(avg('recall') * 100).toFixed(1)}%`);
  console.log(`Precision: ${(avg('precision') * 100).toFixed(1)}%`);
  console.log(`F1:        ${(avg('f1') * 100).toFixed(1)}%`);
  console.log(`Dup Ratio: ${(avg('duplicate_ratio') * 100).toFixed(1)}%`);
  
  const totalTP = allScores.reduce((s, c) => s + c.true_positives, 0);
  const totalExp = allScores.reduce((s, c) => s + c.expected_count, 0);
  console.log(`Overall:   ${totalTP}/${totalExp} findings detected`);
}
