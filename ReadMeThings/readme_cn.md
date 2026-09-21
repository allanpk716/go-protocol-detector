# Go Protocol Detector

[[English]](https://github.com/allanpk716/go-protocol-detector/blob/master/README.md)

简易的网络协议的检测库 —— 同一个二进制，服务两类使用者：

* **AI Agent**：拿到的是机器契约 —— JSONL 输出、语义化退出码、内置能力自描述。入口在
  [AGENT_INSTRUCTION.md](https://github.com/allanpk716/go-protocol-detector/blob/master/AGENT_INSTRUCTION.md)（英文，自包含）。
* **人类**：终端里的扫描工具 —— 进度条、可读的结果汇总、CSV 导出。就是本页剩下的内容。

同一个命令自动适配两种场景：stdout 是终端时输出人类格式；被管道、重定向或 Agent 调用时，
输出恰好一行 JSONL。用 `--format=human` 或 `--format=jsonl` 可以强制指定。

> 还不是正式版本，可能在后续的使用中进行大方向的重构。建议观望下。

## 安装

```bash
# 从 Releases 下载（Linux amd64/arm/arm64、Windows amd64，附校验和）
# https://github.com/allanpk716/go-protocol-detector/releases

# 或用 Go >= 1.24 安装
go install github.com/allanpk716/go-protocol-detector/cmd/go-protocol-detector@latest

# 或从源码构建
git clone https://github.com/allanpk716/go-protocol-detector
cd go-protocol-detector && go build -o go-protocol-detector ./cmd/go-protocol-detector
```

## 使用

```powershell
# RDP 扫描
go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389

# SFTP：无凭据的协议级检测（详见 SFTP_DETECTION_GUIDE.md）
go-protocol-detector --protocol=sftp --host=172.20.65.1/24 --port=22

# RustDesk HBBS 信令服务器检测（端口 21116）
go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116

# RustDesk HBBR 中继服务器检测（端口 21117）
go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117

# RustDesk HBBS TCP 打洞服务检测（端口 21116）
go-protocol-detector --protocol=rustdesk-hbbs-21116 --host=192.168.1.1-254 --port=21116

# 结果输出到 CSV 文件
go-protocol-detector --protocol=ssh --host=192.168.1.0/24 --port=22 --csv-output=results.csv

# 关闭进度条（脚本里常用）
go-protocol-detector --protocol=rdp --host=192.168.1.1-254 --port=3389 --no-progress
```

完整旗标列表看 `go-protocol-detector --help`，或英文 README 里的 CLI reference。

## 支持检测协议

* RDP

* FTP

* SFTP

  > SFTP（SSH 文件传输协议）采用协议分析方式检测，无需认证凭据。
  >
  > 快速三层检测：TCP连接 → SSH协议识别 → SFTP子系统查询。
  >
  > 详见 [SFTP 检测指南](https://github.com/allanpk716/go-protocol-detector/blob/master/SFTP_DETECTION_GUIDE.md)。

* SSH

* VNC

* Telnet

* RustDesk

  > RustDesk 远程桌面软件检测。
  >
  > - **rustdesk-hbbs**：HBBS（信令/注册服务器）检测，端口 21116（protobuf `RegisterPk` 握手）
  > - **rustdesk-hbbr**：HBBR（中继服务器）检测，端口 21117
  > - **rustdesk-hbbs-21116**：HBBS TCP 打洞服务检测，端口 21116
  >
  > 基于 Protobuf 协议检测，可靠识别 RustDesk 服务器。

## 给 AI Agent 使用

stdout 不是终端（被管道、重定向或 Agent 调用）时，工具输出单行 JSONL 结果信封，
而不是人类格式。可用 `--format=jsonl` 显式强制。配套还有语义化退出码（0/2/4/1）、
机器可读的能力自描述（`--self-describe`）、以及不截断的全量结果落盘（`--output-file`）。

完整契约（安装、输出 schema、退出码、错误信封、完整工作流）见
[AGENT_INSTRUCTION.md](https://github.com/allanpk716/go-protocol-detector/blob/master/AGENT_INSTRUCTION.md)。

## TODO

- [ ] 优化 SFTP 检测性能和凭据测试策略

## 如何实现的

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn_tutorial.md)

## 打赏

如果本人做的工具对你有一些帮助，可以请我喝一杯咖啡，或者赞助一点服务器费用。

![收款码](pics/收款码.png)

## 致谢

* [ziutek/telnet](ziutek/telnet)
