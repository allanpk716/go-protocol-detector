# 02 · Detector detailed checks (banner + reason) and pipeline wiring

## What to build
Every protocol check gains a detailed variant returning `CheckDetail{Banner, Reason}` alongside the existing error, and the scan pipeline fills the new `CheckResult.Banner/Reason` fields. Human-mode detection semantics must be provably unchanged: VNC keeps its exact old 4-byte single-read detection (the 12-byte banner continuation happens only after a successful match, bounded ≤500ms, never flips outcome); other protocols execute the identical step sequence; banner capture is scope-limited to ssh/ftp/vnc/sftp per D7.

## 验收标准
- [ ] `CheckDetailed(pt, host, port, user, password, key)` returns `CheckDetail` + error for all 10 protocols
- [ ] `commonCheckDetailed` has `captureBanner bool`; RDP/HBBS/HBBS21116/Common never return a banner
- [ ] Old `VNCHelper.Check()` body byte-for-byte unchanged; new `CheckDetailed()` replicates its detection then best-effort reads 8 more bytes for banner
- [ ] SFTP failures wrap raw net errors with double `%w` (sentinel still `errors.Is`-able); SFTP banner passes `SanitizeBanner`
- [ ] `performProtocolCheck` returns `(bool, string, CheckDetail)`; worker assigns via pre-declared `var detail CheckDetail` (no `:=` with selectors)
- [ ] `TestCheckDetailedVNCPartialDataStillHits` passes: a peer sending only "RFB " is a HIT with empty banner
- [ ] Existing detector tests still pass; `go build ./...`, `go vet ./...` clean

## Blocked by
01

## 涉及路径
- Modify: `pkg/detector.go`
- Modify: `pkg/scan_tools.go`(仅 CheckResult 结构体加 Banner/Reason 两字段)
- Modify: `pkg/scan_core.go`
- Modify: `internal/feature/vnc/vnc.go`
- Modify: `internal/feature/sftp/sftp.go`
- Create: `pkg/check_detailed_test.go`

## 副作用声明
- 独占验证命令: `go test ./pkg/ -run TestCheckDetailed -v && go test ./internal/...`

## decision_refs: D5, D7, D13
## review_blocks: F1(等价保证+钉死测试), F3(范围强制)

> 完整 TDD 步骤与逐行代码:见实施指南 Task 2(随派单包内联)。
