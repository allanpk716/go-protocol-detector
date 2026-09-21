# AGENT_INSTRUCTION.md — go-protocol-detector for AI agents

Multi-protocol port scanner and protocol identifier (RDP, SSH, FTP, SFTP,
Telnet, VNC, RustDesk, generic TCP). Human-oriented docs live in README.md;
this file is the machine-facing contract.

## Quick start

```bash
# One-shot scan; when your stdout is not a terminal you get JSONL automatically.
go-protocol-detector --protocol=ssh --host=192.168.1.0/24 --port=22

# Force the machine format explicitly (recommended for determinism):
go-protocol-detector --format=jsonl --protocol=common --host=10.0.0.1-254 --port=22,80,443

# Ask the tool what it can do before using it:
go-protocol-detector --self-describe --format=jsonl
```

Flag priority: an explicit `--format=human|jsonl` always wins; `--agent`
applies only when `--format` is `auto` or unrecognized; unrecognized
`--format` values fall back to auto (TTY → human, non-TTY → jsonl).

## Output contract (JSONL)

On completion the tool writes exactly ONE JSONL line to stdout:

```json
{"version":"1.0","tool":"go-protocol-detector","type":"result","kind":"scan-result","timestamp":"...","data":{ }}
```

`data` fields:

| field | type | meaning |
|---|---|---|
| `protocol` | string | protocol that was scanned |
| `scan_id` | string | unique scan identifier |
| `targets` | object | `{hosts, ports, total_checks}` |
| `stats` | object | `{duration_ms, hits, negatives, errors}` |
| `hits` | array | `[{host, port, response_time_ms, banner?}]` — port open AND protocol matched |
| `negatives` | object | `{total, by_reason, sample, sample_truncated}` — normal scan data, NOT errors; `sample` is always an array (`[]` when empty) |
| `errors` | object | `{total, sample, sample_truncated}` — scan-level failures worth acting on |
| `output_file` | string? | present only with `--output-file`; the file contains ALL results |

Negative reasons (fixed enum): `closed` (connection refused), `timeout`,
`protocol_mismatch` (TCP open, wrong protocol), `unreachable` (network layer),
`unknown`.

`samples` are capped at 50 entries. For complete data pass `--output-file=<path>`
and read the JSON file — do NOT rescan to recover truncated entries.

`banner` is captured for ssh / ftp / vnc / sftp only (e.g. `SSH-2.0-OpenSSH_8.9`,
`RFB 003.008`); absent otherwise.

## Exit codes

| code | meaning |
|---|---|
| 0 | scan completed — empty result is still success; check `stats.hits` |
| 1 | fatal crash / internal error (see error envelope) |
| 2 | input invalid (unknown flag, invalid value, or host/port/protocol parse failure) |
| 4 | network error: every target unreachable (hits=0, errors=0, all negatives `unreachable`) |
| 3, 5 | reserved, unused |

## Errors

Failures emit `{"type":"error","error_code":"INPUT_INVALID"|"INTERNAL_ERROR"|"FATAL_CRASH","message":"..."}`
and the matching non-zero exit code. This includes CLI usage errors such as
unknown flags. stderr is silent unless `AGENT_DEBUG` is set (e.g. `AGENT_DEBUG=1`).

## Concurrency & limits

Single protocol per invocation (scan multiple protocols by invoking once each).
Limits: 1000 IPs per range, 65536 ports total, 1000 threads (auto-clamped),
500 concurrent connections, 5s read timeout, 1s default connect timeout.
Pass `--thread`/`--timeout` to tune.

## Trace correlation

Set `AGENT_TRACE_ID` in the environment; its value is copied into every
envelope's `trace_id` field.
