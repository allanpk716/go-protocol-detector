# AGENT_INSTRUCTION.md — go-protocol-detector for AI agents

Multi-protocol port scanner and protocol identifier: RDP, SSH, FTP, SFTP,
Telnet, VNC, RustDesk (hbbs / hbbr / hbbs-21116), and generic TCP (`common`).
This file is the machine-facing entry point and is self-contained — you do
not need to read anything else to drive the tool. Human-oriented docs live
in [README.md](./README.md).

Shortcut: the runtime binary carries the same contract —
`go-protocol-detector --self-describe --format=jsonl` prints protocols,
flags, exit codes, limits, and the full data schema as one JSONL line (§2).

## 1. Get the binary

Any one of:

```bash
# a) Download from GitHub Releases
#    Linux (amd64, arm, arm64) and Windows (amd64) binaries + checksums
#    https://github.com/allanpk716/go-protocol-detector/releases

# b) Install with Go >= 1.24
go install github.com/allanpk716/go-protocol-detector/cmd/go-protocol-detector@latest

# c) Build from source
git clone https://github.com/allanpk716/go-protocol-detector
cd go-protocol-detector && go build -o go-protocol-detector ./cmd/go-protocol-detector
```

Verify with `--version` or `--self-describe` (§2).

## 2. Discover capabilities (optional, cheap)

```bash
go-protocol-detector --self-describe --format=jsonl
```

One JSONL line (`kind:"self-describe"`) listing supported protocols (with
auth support), every flag and its default, exit codes, resource limits, and
the complete result data schema. It is the authoritative runtime contract —
when in doubt, trust it over any documentation, including this file. It
costs one process spawn and touches no network.

## 3. Run a scan

```bash
# Non-TTY stdout (piped/redirected/called by you) → JSONL automatically:
go-protocol-detector --protocol=ssh --host=192.168.1.0/24 --port=22

# Force the machine format explicitly (recommended — deterministic everywhere):
go-protocol-detector --format=jsonl --protocol=common --host=10.0.0.1-254 --port=22,80,443
```

- **One protocol per invocation.** To check ssh AND rdp, invoke once each.
- Flag priority: an explicit `--format=human|jsonl` always wins; `--agent`
  applies only when `--format` is `auto` or unrecognized; unrecognized
  `--format` values fall back to auto (TTY → human, non-TTY → jsonl).
- sftp is credential-free protocol detection; `--user` / `--password` /
  `--prikey` do not affect it (details in
  [SFTP_DETECTION_GUIDE.md](./SFTP_DETECTION_GUIDE.md)).
- Tune with `--thread` (default 10, max 1000) and `--timeout` (ms, default
  1000). Limits are listed at the end of this file.

## 4. Read the result

On completion the tool writes exactly ONE JSONL line to stdout. stderr is
silent unless `AGENT_DEBUG=1`. Real output — one open port and one closed
port on localhost (`--protocol=common --host=127.0.0.1 --port=46511,46512`):

```json
{"version":"1.0","tool":"go-protocol-detector","type":"result","timestamp":"2026-09-21T07:42:05Z","data":{"protocol":"common","scan_id":"scan_1789976525","targets":{"hosts":1,"ports":2,"total_checks":2},"stats":{"duration_ms":1,"hits":1,"negatives":1,"errors":0},"hits":[{"host":"127.0.0.1","port":46511,"response_time_ms":1}],"negatives":{"total":1,"by_reason":{"closed":1},"sample":[{"host":"127.0.0.1","port":46512,"reason":"closed"}],"sample_truncated":false},"errors":{"total":0,"sample":[],"sample_truncated":false}},"kind":"scan-result"}
```

`data` fields:

| field | type | meaning |
|---|---|---|
| `protocol` | string | protocol that was scanned |
| `scan_id` | string | unique scan identifier |
| `targets` | object | `{hosts, ports, total_checks}` |
| `stats` | object | `{duration_ms, hits, negatives, errors}` |
| `hits` | array | `[{host, port, response_time_ms, banner?}]` — port open AND protocol matched; **always complete, never truncated** |
| `negatives` | object | `{total, by_reason, sample, sample_truncated}` — normal scan data, NOT errors; `sample` is always an array (`[]` when empty), capped at 50 |
| `errors` | object | `{total, sample, sample_truncated}` — scan-level failures worth acting on; `sample` capped at 50 |
| `output_file` | string? | present only with `--output-file`; the file contains ALL results |

Negative reasons (fixed enum): `closed` (connection refused), `timeout`,
`protocol_mismatch` (TCP open, wrong protocol), `unreachable` (network layer),
`unknown`.

`banner` is captured for ssh / ftp / vnc / sftp hits only (e.g.
`SSH-2.0-OpenSSH_8.9`, `RFB 003.008`); the key is absent for other protocols.

## 5. Exit codes

| code | meaning |
|---|---|
| 0 | scan completed — empty result is still success; check `stats.hits` |
| 1 | fatal crash / internal error (see error envelope) |
| 2 | input invalid (unknown flag, invalid value, or host/port/protocol parse failure) |
| 4 | network error: every target unreachable (hits=0, errors=0, all negatives `unreachable`) |
| 3, 5 | reserved, unused |

## 6. Errors

Failures emit ONE error envelope instead of a result envelope. Real output —
`--protocol=bogus` (exit 2):

```json
{"version":"1.0","tool":"go-protocol-detector","type":"error","timestamp":"2026-09-21T07:40:20Z","error_code":"INPUT_INVALID","message":"unknown protocol: \"bogus\""}
```

Error codes: `INPUT_INVALID` (exit 2), `INTERNAL_ERROR` and `FATAL_CRASH`
(exit 1). CLI usage errors such as unknown flags produce the same envelope
shape with exit 2. Set `AGENT_DEBUG=1` to let stderr logs through when
debugging; without it stderr stays empty in machine mode.

## 7. Full data when samples are truncated

`negatives.sample` and `errors.sample` are capped at 50 entries (their
totals stay exact; `sample_truncated` tells you when the cap applied). The
`hits` array is never truncated. When you need every negative/error entry,
pass `--output-file=<path>`: the file gets ALL results (no truncation,
deterministic host-then-port order) and the envelope carries only the path
in `data.output_file`. Read that file — do NOT rescan to recover truncated
entries.

Real file content from a `--protocol=common` run against a closed port:

```json
{
  "protocol": "common",
  "scan_id": "scan_1789976377",
  "timestamp": "2026-09-21T07:39:37Z",
  "hits": [],
  "negatives": [
    {
      "host": "127.0.0.1",
      "port": 46511,
      "reason": "closed"
    }
  ],
  "errors": []
}
```

## 8. Trace correlation

Set `AGENT_TRACE_ID` in the environment; its value is copied into every
envelope's `trace_id` field.

## 9. Typical workflow

```bash
export AGENT_TRACE_ID="my-task-42"

# 1) (optional) confirm capabilities at runtime
go-protocol-detector --self-describe --format=jsonl

# 2) scan — force JSONL, keep full data on disk
go-protocol-detector --format=jsonl --protocol=ssh --host=10.0.0.0/24 \
    --port=22 --output-file=/tmp/ssh-full.json
echo $?   # 0 completed / 2 bad input / 4 all unreachable / 1 fatal

# 3) branch on exit code and data
#    exit 0, stats.hits > 0  → hits[] carries host/port/response_time_ms/banner
#    exit 0, stats.hits == 0 → empty result is SUCCESS; negatives[] says why
#    exit 2                  → your flags are wrong; fix and retry
#    exit 4                  → nothing reachable at network level; report, stop
#    exit 1                  → tool failed; error envelope on stdout has why

# 4) need all negatives, not just the 50-sample? read /tmp/ssh-full.json

# 5) another protocol? another invocation
go-protocol-detector --format=jsonl --protocol=rdp --host=10.0.0.0/24 --port=3389
```

## Limits

- Host ranges: 1000 IPs per range
- Ports: 65536 total per invocation
- Threads: default 10, max 1000 (auto-clamped)
- Max 500 concurrent connections
- Connect timeout: default 1000 ms (`--timeout`); read timeout 5 s
