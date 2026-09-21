# 04 · Agent report builder

## What to build
A pure function that assembles the machine report (`AgentReportData`) from raw `CheckResult`s: hit/negative/error trichotomy, five-reason counts, deterministic host-then-numeric-port ordering, 50-entry sample truncation with flags, and the conservative all-unreachable predicate for exit 4.

## 验收标准
- [ ] `BuildAgentReport(protocol, scanID, results, hostsCount, portsCount, durationMs, sampleLimit, outputFile)` produces the D14 schema
- [ ] Classification: Success→hit; !Success&&Reason→negative(reason); !Success&&!Reason→error(ErrorMessage)
- [ ] Samples capped at `DefaultSampleLimit=50` (clamp ≤0 to default); `sample_truncated` correct
- [ ] Zero-entry samples serialize as `[]`, never `null` (pinned by `TestBuildAgentReportEmptySamplesSerializeAsArrays`)
- [ ] Sorting deterministic: host asc, then numeric port asc
- [ ] `IsAllUnreachable`: hits=0 ∧ errors=0 ∧ negatives>0 ∧ by_reason[unreachable]==negatives
- [ ] All builder tests pass; `go build ./...` clean

## Blocked by
02

## 涉及路径
- Create: `pkg/agent_report.go`
- Create: `pkg/agent_report_test.go`

## 副作用声明
- 独占验证命令: `go test ./pkg/ -run 'TestBuildAgentReport|TestIsAllUnreachable' -v`

## decision_refs: D4, D5, D6, D8, D14
## review_blocks: F10([] 非 null)

> 完整 TDD 步骤与逐行代码:见实施指南 Task 4(随派单包内联)。
