# 08 · Dual documentation — AGENT_INSTRUCTION.md, README, CLAUDE.md

## What to build
The agent-facing contract document (English, repo root) plus targeted human-doc updates: README gets an "Using with AI agents" section, CLAUDE.md gets agent-mode usage examples.

## 验收标准
- [ ] `AGENT_INSTRUCTION.md` covers: quick start, flag priority rule, output contract table (incl. samples-are-arrays note), negative reasons enum, exit codes incl. usage errors, errors/stderr/AGENT_DEBUG, limits, trace correlation
- [ ] README links to AGENT_INSTRUCTION.md from the new section
- [ ] CLAUDE.md "Running the Application" shows --format=jsonl / --self-describe / --output-file examples
- [ ] No behavior claims absent from the implementation (banner scope, 50 cap, exit table)

## Blocked by
07

## 涉及路径
- Create: `AGENT_INSTRUCTION.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`

## 副作用声明
- 无独占验证命令(文档;默认只跑类型检查)

## decision_refs: D1, D9, D14
## review_blocks: 无

> 完整文档底稿:见实施指南 Task 8(随派单包内联)。
