# docs/ — index

Maintainer-facing material: implementation notes, research, decisions, and
historical plans. User-facing docs live elsewhere:

- Humans: [../README.md](../README.md)
- AI agents: [../AGENT_INSTRUCTION.md](../AGENT_INSTRUCTION.md) (machine contract)
- SFTP detection deep-dive: [../SFTP_DETECTION_GUIDE.md](../SFTP_DETECTION_GUIDE.md)
- RustDesk module internals: [../internal/feature/rustdesk/README.md](../internal/feature/rustdesk/README.md)

## Directory layout

| path | content |
|---|---|
| `adr/` | Architecture Decision Records (JSONL-as-contract, TTY autodetect) |
| `research/` | Protocol research (RustDesk HBBS detection) |
| `plans/` | Historical implementation plans (RustDesk detection, code-review improvements) |
| `superpowers/` | Spec + plan from the 2026-09 agent-mode phase 1 work |

## Topic documents

- [progress-bars.md](./progress-bars.md) — dual progress bar implementation (mpb), cross-platform behavior
- [goreleaser-local-testing.md](./goreleaser-local-testing.md) — 本地验证 GoReleaser 构建配置的流程
- [rustdesk-quick-reference.md](./rustdesk-quick-reference.md) — RustDesk detection command cheat sheet
- [rustdesk-21115-research-summary.md](./rustdesk-21115-research-summary.md) — 为什么不检测 21115 端口的研究结论

## Project glossary

Domain terms (hit / negative result / error / empty success / banner) are
defined in [../CONTEXT.md](../CONTEXT.md).
