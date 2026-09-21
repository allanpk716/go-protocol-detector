# go-protocol-detector Agent Mode — Phase 1 Spec

Date: 2026-09-21 · Status: accepted (night chain, review converged after 1 revision)
Source: reviewed plan `.xcheck/20260921-124508/proposal.md` (rev1) + decisions.md + FINDINGS.md of the same ring.

## Problem Statement

The tool's output targets humans: timestamped logs on stderr, a human-only result block, successes printed but failures discarded, and a single non-semantic exit code. An AI agent calling it through a shell gets noise it must filter, no machine-readable data, no failure taxonomy, and no way to discover capabilities. We need a machine-native contract while keeping the human terminal experience unchanged.

## Solution

When stdout is not a terminal (or `--format=jsonl` / `--agent` is given), the tool runs the same scan but emits exactly one JSONL result envelope (protocol v1.0, `kind="scan-result"`) on stdout, keeps stderr silent (unless `AGENT_DEBUG=1`), and exits with semantic codes (0 completed / 2 invalid input incl. CLI usage errors / 4 all-unreachable / 1 fatal). Negative results (closed ports, protocol mismatches) are data with a fixed five-reason enum, separate from actionable errors. Samples are truncated at 50 with full data available via `--output-file`. `--self-describe` emits a machine-readable capability dump. Human mode on a terminal is byte-for-byte the previous behavior.

Glossary terms (命中 hit / 负结果 negative result / 错误 error / 空结果成功 empty success / banner / negative reason enum) are defined in `CONTEXT.md`. Architecture decisions: ADR-0001 (CLI JSONL as the contract, MCP later), ADR-0002 (TTY autodetect output mode).

## User Stories

1. As an AI agent, I want machine-readable output by default when my stdout is not a terminal, so that I can parse results without flags or help-reading.
2. As an AI agent, I want to force the machine format explicitly, so that output is deterministic in any environment.
3. As an AI agent, I want one final envelope per run, so that I consume a single JSON line instead of streamed noise.
4. As an AI agent, I want negative results classified into a fixed enum (`closed|timeout|protocol_mismatch|unreachable|unknown`), so that I can branch without string matching.
5. As an AI agent, I want scan-level errors separated from negative results, so that I act only on actionable failures.
6. As an AI agent, I want an empty-but-successful scan to exit 0 with counts in data, so that "nothing found" differs from "tool failed".
7. As an AI agent, I want samples capped at 50 with totals, so that large scans don't flood my context.
8. As an AI agent, I want full results in a JSON file with the envelope carrying only the path, so that I can read complete data when needed.
9. As an AI agent, I want service banners (ssh/ftp/vnc/sftp) on hits, so that I can identify service versions.
10. As an AI agent, I want a machine-readable capability dump (`--self-describe`), so that I can discover protocols, flags, exit codes and limits before first use.
11. As an AI agent, I want semantic exit codes including CLI usage errors, so that I can branch on failure category.
12. As an AI agent, I want stderr silent by default, so that nothing pollutes my capture; humans debugging can set `AGENT_DEBUG=1`.
13. As an AI agent, I want `AGENT_TRACE_ID` propagated into the envelope `trace_id`, so that scans correlate across my orchestration.
14. As a human, I want the terminal experience unchanged (progress bars, result block, CSV output), so that existing workflows keep working.
15. As a human, I want to force human-readable output when redirecting, so that piped output stays readable.
16. As a developer, I want human-mode detection semantics provably unchanged, so that the refactor is safe to ship.

## Implementation Decisions

- **Output contract**: SDK envelope v1.0; final scan result = one `type=result, kind="scan-result"` line; capability dump = one `kind="self-describe"` line; failures = `type=error` envelopes with `error_code` strings. SDK `Writer` is used directly (the SDK's `App.Execute` is cobra-bound; the tool stays on urfave/cli).
- **Flag priority (binding rule)**: explicit `--format=human|jsonl` always wins; `--agent` applies only when `--format` is `auto` or unrecognized; unrecognized values fall back to auto behavior (documented semantics, not an error).
- **Data schema**: `protocol`, `scan_id`, `targets{hosts,ports,total_checks}`, `stats{duration_ms,hits,negatives,errors}`, flat `hits[{host,port,response_time_ms,banner?}]` (int ports, no per-hit timestamp), `negatives{total,by_reason,sample,sample_truncated}`, `errors{total,sample,sample_truncated}`, optional `output_file`. Samples are JSON arrays (`[]` when empty, never `null`), capped at a constant 50, no flag.
- **Classification rule**: `Success=true` → hit; `Success=false && Reason set` → negative; `Success=false && Reason empty` → error (cancellation/resource-denial/panic).
- **Negative reason mapping**: connection refused → `closed`; network-layer unreachable → `unreachable`; timeouts → `timeout`; feature mismatch / EOF after connect → `protocol_mismatch`; else `unknown`. Wrapped error chains must keep the raw network error reachable (`errors.As`) — double-`%w` wrapping where a sentinel is also preserved.
- **Banner scope & rules**: captured for ssh/ftp/vnc/sftp only; printable-ASCII prefix, stop at first CR/LF or non-printable byte, max 128 bytes, fewer than 4 printable bytes yields "".
- **Human-mode equivalence guarantees (D13)**: the shared pipeline switch must be observationally identical for humans — VNC keeps its exact old 4-byte single-read detection; the 12-byte banner continuation happens only after a successful match, is bounded (≤500ms), and never flips the outcome (pinned by a partial-data test). SFTP keeps the same detection path; its error chain may wrap the raw cause with double-`%w` (sentinel still `errors.Is`-able; the added text is not part of human-visible output). Other protocols execute the identical step sequence. The only accepted visible change: input-validation error text gains a `[VALIDATION]` prefix (typed for exit-code classification).
- **Exit codes**: 0 scan completed (empty result is success); 2 INPUT_INVALID — host/port/protocol parse failures AND CLI usage errors (unknown flag, invalid value) via a usage-error hook that, in machine context (stdout not a terminal), emits one error envelope and stays stderr-silent; 4 NETWORK_ERROR — conservative: hits=0, errors=0, and every negative is `unreachable`; 1 FATAL_CRASH/INTERNAL_ERROR (panic recovery emits the envelope). 3 and 5 reserved, documented as unused.
- **Trace correlation**: `AGENT_TRACE_ID` → envelope `trace_id`, wired explicitly at every writer construction (the SDK writer does not read the env by itself).
- **stderr discipline**: in machine mode all `log` output is discarded unless `AGENT_DEBUG=1`.
- **Full results file**: `--output-file <path>` writes complete non-truncated results as indented JSON (deterministic host-then-port order); the envelope carries the path.

## Testing Decisions

- No live services or `.env` required: local `127.0.0.1` listeners on ephemeral ports everywhere (repo precedent: existing table-driven tests in `pkg`).
- Unit tests: error-classifier (incl. wrapped-chain semantics), banner sanitizer (boundary cases, 128 cap), report builder (classification, truncation, `[]`-not-`null`, sorting, all-unreachable predicate), envelope emission (single JSONL line, head fields, data round-trip), self-describe payload shape, flag resolution (priority rule incl. explicit-beats-agent and unknown-fallback), exit-code classification.
- Per-protocol detailed-check tests: hit with banner (ssh, vnc), closed port → `closed`, junk banner → `protocol_mismatch`, and the VNC partial-data pin (4-byte peer still hits).
- Human-mode regression: scan-with-retention test asserts old success/failed maps unchanged alongside the new full-results list.
- End-to-end against the built binary: piped auto → JSONL + exit 0; forced human; closed port → negative not error + exit 0; invalid host / unknown protocol / unknown flag → error envelope + exit 2; self-describe; output-file round-trip (file content matches envelope pointer).
- External behavior only; no tests of internal helpers beyond what the contract needs.

## Out of Scope

- Multi-protocol single invocation (`--protocol=rdp,ssh`) — phase 2.
- Streaming output (`--stream`) — phase 2.
- Resume exposure to agents (`--resume`) — phase 2.
- MCP wrapper — phase 2 (ADR-0001).
- Spec chapter-3 meta-commands beyond `--self-describe`.
- Rejecting unrecognized `--format` values (documented fallback; tightening to exit 2 awaits an explicit user decision).
- Exit-4 end-to-end test (unit coverage exists; adoption pending user decision).
- Trace-id pinning test (suggestion; adoption pending).

## Further Notes

- Non-blocking suggestions F11–F16 are recorded in the review ledger (`.xcheck/20260921-124508/FINDINGS.md`); none are requirements of this spec.
- The reviewed plan (rev1) carries the full TDD task breakdown with code; it is the implementation guide for the tickets.
- Ledger facts verified during review: SDK `Writer.Success/ErrorWithCode/SetTraceID` exist (writer.go:52 etc.); `ScanContext.GetElapsedDuration()` exists; urfave/cli v2.11.1 has `App.OnUsageError`; old HBBR check is write-only (equivalence holds).
