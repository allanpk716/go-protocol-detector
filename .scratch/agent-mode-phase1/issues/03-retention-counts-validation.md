# 03 · Full-result retention, host/port counts, input-error typing

## What to build
The scan pipeline retains every `CheckResult` (not just success/fail maps), the scan context records host/port counts, host/port input-shape errors become VALIDATION-typed, and `IsKnownProtocol` lets the CLI reject unknown protocol names.

## 验收标准
- [ ] `OutputInfo.AllResults []CheckResult` appended by the collector under the existing mutex
- [ ] `ScanContext.HostsCount` / `PortsCount` set by `ScanWithOutput`
- [ ] All `fmt.Errorf` returns in `parseHost`/`parsePort` become `errors.NewValidationError(...)` (text gains `[VALIDATION]` prefix — the one documented human-mode exception)
- [ ] `IsKnownProtocol` recognizes exactly the 10 protocol names (case-sensitive)
- [ ] `TestScanWithOutputRetainsAllResults`: 1 open + 1 closed port → AllResults has 2 entries, hit has empty reason, closed entry has reason "closed"; ctx counts 1/2
- [ ] Existing validation tests still pass (update exact-text assertions to accept the prefix if any)

## Blocked by
02

## 涉及路径
- Modify: `pkg/scan_tools.go`(OutputInfo、parseHost/parsePort、IsKnownProtocol)
- Modify: `pkg/scan_core.go`(collector append)
- Modify: `pkg/scan_context.go`(两个字段)
- Create: `pkg/scan_retention_test.go`

## 副作用声明
- 独占验证命令: `go test ./pkg/ -run 'TestScanWithOutputRetainsAllResults|TestIsKnownProtocol|TestParseHostInvalid' -v && go test ./pkg/`

## decision_refs: D8, D13
## review_blocks: 无(F2 类分类已由 01/02 覆盖)

> 完整 TDD 步骤与逐行代码:见实施指南 Task 3(随派单包内联)。
