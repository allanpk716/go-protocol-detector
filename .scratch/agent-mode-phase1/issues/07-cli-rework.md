# 07 · CLI rework — flags, format resolution, exit codes, agent path

## What to build
The CLI entry gains `--format=auto|human|jsonl` + `--agent` + `--output-file` + `--self-describe`, TTY autodetection, the binding flag-priority rule, semantic exit codes with a usage-error envelope path, AGENT_TRACE_ID wiring, stderr silence in machine mode, and the agent scan flow (report → optional file → envelope → exit code). Human path stays verbatim.

## 验收标准
- [ ] Priority rule pinned by `TestResolveFormat`: explicit `--format` ALWAYS wins; `--agent` only for auto/unrecognized; unrecognized falls back to auto
- [ ] `newAgentWriter()` wires `AGENT_TRACE_ID`→`SetTraceID`; all three call sites (OnUsageError, self-describe, runAgentScan) use the factory
- [ ] `app.OnUsageError`: TTY → default error; non-TTY → one INPUT_INVALID envelope + empty-message exit 2, stderr silent
- [ ] Agent scan: protocol/host/port validation → exit 2 envelope; scan errors classified (VALIDATION/RESOURCE→2, else 1); success → report + envelope; all-unreachable → exit 4 (envelope already emitted)
- [ ] `AGENT_DEBUG` unset → `log.SetOutput(io.Discard)` in machine mode
- [ ] Human path code identical to current behavior
- [ ] `go test ./cmd/...`, `go build ./...`, `go vet ./...` clean; `pkg/sdk_dependency.go` deleted

## Blocked by
03, 04, 05, 06

## 涉及路径
- Modify: `cmd/go-protocol-detector/main.go`(全量重写,人类路径逐字保留)
- Create: `cmd/go-protocol-detector/main_test.go`
- Delete: `pkg/sdk_dependency.go`

## 副作用声明
- 独占验证命令: `go test ./cmd/... -v && go build ./... && go vet ./...`

## decision_refs: D3, D4, D6, D8, D10, D11, D12
## review_blocks: F4(优先级规则), F5(usage-error 信封), F8(trace 接线)

> 完整 TDD 步骤与逐行代码(含整份 main.go):见实施指南 Task 7(随派单包内联)。
