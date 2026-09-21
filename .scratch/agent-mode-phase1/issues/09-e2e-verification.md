# 09 · End-to-end tests and full verification

## What to build
E2E coverage against the built binary exercising the whole agent contract: piped auto→JSONL, forced human, closed-port negative, invalid host/protocol/flag → exit 2 + envelope, self-describe, output-file round-trip — plus the full verification sweep.

## 验收标准
- [ ] TestMain builds the binary once via `go build -o`
- [ ] All E2E tests pass: AutoFormatIsJSONLWhenPiped / ForcedHumanFormat / ClosedPortIsNegativeNotError / InvalidHostExits2 / InvalidProtocolExits2 / UnknownFlagExits2 / SelfDescribe / OutputFile
- [ ] Full sweep green: `go build -o go-protocol-detector.exe ./cmd/go-protocol-detector`, `go vet ./...`, `go test ./internal/... ./pkg/... ./cmd/...`

## Blocked by
07

## 涉及路径
- Create: `cmd/go-protocol-detector/main_e2e_test.go`

## 副作用声明
- 独占验证命令: `go test ./cmd/... -v`(会构建临时二进制;与 07 的验证互斥,依赖 07 已完成)

## decision_refs: D3, D4, D6, D8, D9
## review_blocks: F5(unknown-flag E2E)

> 完整测试代码:见实施指南 Task 9(随派单包内联)。exit-4 E2E 属 F11 建议未采纳,不添加。
