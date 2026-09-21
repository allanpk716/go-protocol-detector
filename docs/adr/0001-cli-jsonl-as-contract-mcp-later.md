# CLI JSONL 为契约本体，MCP 二期薄包装

go-protocol-detector 要面向 AI Agent 使用，MCP server 和 CLI+JSONL 是两条可行通路。决定：以 CLI 的 JSONL 信封输出为唯一契约本体（复用 ai-agent-cli-rules SDK 与信封规范），MCP 留作二期薄包装（subprocess 调 CLI 或直接 import pkg）。

理由：CLI 能被所有能开 shell 的 Agent 使用（MCP 只覆盖装了 client 的宿主）；已有的 SDK 与规范投入全是 CLI 形态；分钟级长扫描在独立进程模型下比 MCP 工具调用更抗超时；且两者共享同一个 data schema——MCP 包装时把 JSONL 的 data 原样作为工具返回值即可，先做 CLI 不浪费任何设计。

## Considered Options

- 全量 MCP server 一期实现：覆盖面窄、双接口维护、长扫描超时风险，弃。
- CLI 与 MCP 双轨并行一期：双倍接口面积，无增量收益，弃。
