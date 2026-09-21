# TTY 自动检测决定输出模式

工具定位 Agent 优先但保留人类使用。决定：stdout 为 TTY 时输出人类模式，非 TTY（管道、重定向、Agent 调用）时输出 JSONL；`--format=human|jsonl` 强制指定，`--agent` 作为 `--format=jsonl` 的别名保留。

理由：Agent 不带任何参数即拿到机器格式（Agent 优先的自然形态）；人类在终端的体验完全不变；代码中已有先例（mpb 进度条按 TTY 自动启停）。

## Consequences

- 人类把输出重定向到文件慢慢看时，默认拿到的是 JSONL——这是**故意的行为**，不是 bug，与 ripgrep/jq 类工具的 auto 检测惯例一致；此类用户应加 `--format=human`。
