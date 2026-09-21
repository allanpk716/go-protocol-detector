# 06 · Envelope emission and self-describe data

## What to build
SDK-backed emission of the final `kind="scan-result"` envelope and the `kind="self-describe"` capability dump (protocols with auth_support, flags, exit codes incl. reserved 3/5, limits, data_schema text).

## 验收标准
- [ ] `EmitScanResultEnvelope` / `EmitSelfDescribeEnvelope` write exactly one JSONL line each via `agentsdk.Writer.Success(data, kind)`
- [ ] Envelope head: version 1.0, tool go-protocol-detector, type result, correct kind; data round-trips into `AgentReportData`
- [ ] `BuildSelfDescribeData`: 10 protocols (sftp=optional auth), 14 flags, exit codes {0,1,2,3,4,5} with 3/5 marked reserved, 6 limits, non-empty data_schema containing "scan-result"
- [ ] Tests pass via TDD; `go build ./...` clean

## Blocked by
04

## 涉及路径
- Create: `pkg/agent_output.go`
- Create: `pkg/agent_output_test.go`

## 副作用声明
- 独占验证命令: `go test ./pkg/ -run 'TestEmitScanResultEnvelope|TestBuildSelfDescribeData' -v`

## decision_refs: D4, D9, D15
## review_blocks: 无(SDK 符号已核实存在)

> 完整 TDD 步骤与逐行代码:见实施指南 Task 6(随派单包内联)。
