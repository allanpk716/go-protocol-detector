# 05 · Full-results JSON file writer

## What to build
`WriteFullResultsJSON` writes the complete, non-truncated result set (all negatives and errors) as indented JSON with a deterministic order — the `--output-file` escape hatch for the 50-entry sample cap.

## 验收标准
- [ ] `FullScanResults` carries protocol/scan_id/timestamp + full hits/negatives/errors arrays
- [ ] 120 negatives → file contains all 120 (no truncation)
- [ ] Deterministic host-then-port order; round-trip unmarshal matches
- [ ] Tests pass via TDD; `go build ./...` clean

## Blocked by
04

## 涉及路径
- Create: `pkg/full_results.go`
- Create: `pkg/full_results_test.go`

## 副作用声明
- 独占验证命令: `go test ./pkg/ -run TestWriteFullResultsJSON -v`

## decision_refs: D6, D14
## review_blocks: 无

> 完整 TDD 步骤与逐行代码:见实施指南 Task 5(随派单包内联)。
