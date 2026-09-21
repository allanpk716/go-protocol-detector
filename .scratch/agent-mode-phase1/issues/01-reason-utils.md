# 01 · Negative-reason classifier and banner sanitizer

## What to build
A pure utility layer that maps network errors to the fixed five-value negative-reason enum (`closed|timeout|protocol_mismatch|unreachable|unknown`) and sanitizes raw protocol responses into safe banner strings (printable-ASCII prefix, max 128 bytes, min 4 chars). This is the foundation every protocol check and the agent report depend on. Terms: CONTEXT.md 负结果原因/banner.

## 验收标准
- [ ] `ClassifyNetError` maps: nil→unknown; ECONNREFUSED→closed; EHOSTUNREACH/ENETUNREACH→unreachable; net.Error Timeout()→timeout; io.EOF/ErrUnexpectedEOF→protocol_mismatch; anything else→unknown
- [ ] Wrapped double-`%w` chains keep sentinel `errors.Is`-able AND classify through to the raw network error
- [ ] `SanitizeBanner` stops at first CR/LF/non-printable; caps at 128; under 4 printable chars returns ""
- [ ] All tests in `internal/utils/reason_test.go` pass via TDD (red first, then green)
- [ ] `go build ./...` clean

## Blocked by
无,可立即开始

## 涉及路径
- Create: `internal/utils/reason.go`
- Create: `internal/utils/reason_test.go`

## 副作用声明
- 独占验证命令: `go test ./internal/utils/ -run 'TestClassify|TestSanitize' -v`(仅本包)

## decision_refs: D5, D7
## review_blocks: F2(链上分类测试), F3(清洗规则)

> 完整 TDD 步骤与逐行代码:见实施指南 Task 1(随派单包内联)。
