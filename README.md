# Go Protocol Detector

[[中文]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn.md)

Network protocol detector — one binary, two audiences:

* **AI agents** get a machine contract: JSONL output, semantic exit codes,
  and a built-in capability dump. Start at
  [AGENT_INSTRUCTION.md](./AGENT_INSTRUCTION.md) — it is self-contained.
* **Humans** get a terminal tool with progress bars, a readable result
  block, and CSV export. That is the rest of this page.

The same command serves both: when stdout is a terminal you get human
output; when it is piped, redirected, or called by an agent you get exactly
one JSONL line. Force either mode with `--format=human` or `--format=jsonl`.

**Not Stable Version !**

May be refactored in future use.

## Install

```bash
# Download a release binary (Linux amd64/arm/arm64, Windows amd64, + checksums)
# https://github.com/allanpk716/go-protocol-detector/releases

# Or install with Go >= 1.24
go install github.com/allanpk716/go-protocol-detector/cmd/go-protocol-detector@latest

# Or build from source
git clone https://github.com/allanpk716/go-protocol-detector
cd go-protocol-detector && go build -o go-protocol-detector ./cmd/go-protocol-detector
```

## How to use

### Use From Code:

* [detector_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/pkg/detector_test.go)
* [scan_tools_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/pkg/scan_tools_test.go)

### Use From Executable Program:

[Releases](https://github.com/allanpk716/go-protocol-detector/releases)

```powershell
NAME:
   go-protocol-detector - use like: go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389

USAGE:
   go-protocol-detector [global options] command [command options] [arguments...]

VERSION:
   v0.16.0

DESCRIPTION:
   Multi-protocol scan tool

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --agent              prefer JSONL output (applies only when --format is auto/unrecognized) (default: false)
   --csv-output value   output scan results to CSV file (specify file path to enable CSV output)
   --format value       output format: auto | human | jsonl (explicit value always wins; unrecognized values fall back to auto) (default: "auto")
   --help, -h           show help (default: false)
   --host value         support 3 diffs types: 192.168.1.1,192.168.1.100-254,192.168.1.0/24
   --no-progress, --np  disable progress bar output (default: false)
   --output-file value  write full scan results (all negatives included, no truncation) as JSON to this file
   --password value     if you scan sftp, need give a Password: root (default: "root")
   --port value         support like: 22,80,443,3380-3390
   --prikey value       if you scan sftp, need give a pri key Full Path( user name or this priKeyFPath only chose one): ~/.ssh/id_rsa (default: "~/.ssh/id_rsa")
   --protocol value     select only one protocol: common | ftp | rdp | rustdesk-hbbs | rustdesk-hbbr | rustdesk-hbbs-21116 | sftp | ssh | telnet | vnc (default: "common")
   --self-describe      print machine-readable capability description (JSONL when not human) and exit (default: false)
   --thread value       10 (default: 10)
   --timeout value      1000 ms (default: 1000)
   --user value         if you scan sftp, need give a UserName: root (default: "root")
   --version, -v        print the version (default: false)
```

Example:

```powershell
go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389

go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389,1024-2000

# SFTP: credential-free protocol detection (see SFTP_DETECTION_GUIDE.md)
go-protocol-detector --protocol=sftp --host=172.20.65.1/24 --port=22

# RustDesk HBBS detection (port 21116)
go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116

# RustDesk HBBR detection (port 21117)
go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117

# RustDesk HBBS-21116 detection (TCP hole punching on port 21116)
go-protocol-detector --protocol=rustdesk-hbbs-21116 --host=192.168.1.1-254 --port=21116

# Output results to CSV file
go-protocol-detector --protocol=ssh --host=192.168.1.0/24 --port=22 --csv-output=results.csv

# Disable progress bar (useful in scripts)
go-protocol-detector --protocol=rdp --host=192.168.1.1-254 --port=3389 --no-progress
```

## Support Protocol

* RDP

* FTP

* SFTP

  > SFTP (SSH File Transfer Protocol) detection using protocol analysis.
  >
  > Detects SSH service and SFTP subsystem availability without authentication.
  >
  > Fast 3-layer detection: TCP connection → SSH protocol identification → SFTP subsystem query.
  >
  > Details: [SFTP_DETECTION_GUIDE.md](./SFTP_DETECTION_GUIDE.md)

* SSH

* VNC

* Telnet

* RustDesk

  > RustDesk remote desktop software detection.
  >
  > - **rustdesk-hbbs**: HBBS (Rendezvous/Signaling Server) detection on port 21116 (protobuf `RegisterPk` handshake)
  > - **rustdesk-hbbr**: HBBR (Relay Server) detection on port 21117
  > - **rustdesk-hbbs-21116**: HBBS TCP hole punching service detection on port 21116 (protobuf `RegisterPk` handshake)
  >
  > Uses protobuf-based detection for reliable RustDesk server identification.

## Using with AI agents

When stdout is not a terminal (piped, redirected, or called by an agent), the
tool emits a single-line JSONL result envelope instead of human output.
Force it explicitly with `--format=jsonl`. Semantic exit codes (0/2/4/1), a
machine-readable capability dump (`--self-describe`), and full non-truncated
results via `--output-file` are included.

The complete contract — install, output schema, exit codes, error envelopes,
worked workflow — lives in [AGENT_INSTRUCTION.md](./AGENT_INSTRUCTION.md).

## TODO

- [ ] Optimize SFTP detection performance and credential testing strategy

## Give a reward

If the tools I have made are of some help to you, you can buy me a cup of coffee or sponsor a little server fee.

![收款码](ReadMeThings/pics/收款码.png)

## How to implement

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn_tutorial.md)

## Thanks

* [ziutek/telnet](ziutek/telnet)
