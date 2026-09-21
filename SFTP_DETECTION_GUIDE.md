# SFTP 协议检测指南

本指南描述 go-protocol-detector **当前实现**的 SFTP 检测行为（代码：
`internal/feature/sftp/sftp.go`），包括它的能力边界——尤其是"什么情况下检测不到"。
文末附历史变更说明（旧版策略与旧字段名）。

## 检测原理：三层协议检测，无需凭据

`--protocol=sftp` 对每个目标执行三步：

| 层 | 动作 | 判定 |
|---|---|---|
| 1. TCP 连接 | 向目标端口发起 TCP 连接 | 连不上 → 按网络错误分类（`closed` / `timeout` / `unreachable`） |
| 2. SSH 识别 | 读取服务返回的 banner（读超时 2 秒） | 不以 `SSH-` 开头 → `protocol_mismatch`；通过则记录 banner 与版本 |
| 3. SFTP 子系统确认 | 另建一条连接完成 SSH 握手（专用用户名 `protocol-detector`、无认证、客户端版本 `SSH-2.0-ProtocolDetector`），成功后开 session 通道发送 `sftp` subsystem 请求 | 握手或子系统请求未通过 → `protocol_mismatch`；子系统确认支持 → 命中 |

命中时结果里的 `banner` 字段携带 SSH banner（如 `SSH-2.0-OpenSSH_8.9`）。

## 重要边界：需要认证的 SSH 服务器会报 `protocol_mismatch`

第三层的 SSH 握手**不带任何凭据**。绝大多数 SSH 服务器要求认证，握手会在认证阶段
失败，第三层无法完成 → 最终结果是 `protocol_mismatch`，**即使该服务器确实开着
SFTP**。这是当前实现的刻意取舍：检测器不做认证尝试，宁可报不出，也不猜。

实测示例（github.com:22，一台真实的 OpenSSH 服务）：

```bash
$ go-protocol-detector --format=jsonl --protocol=ssh --host=<github-ip> --port=22
# → hit, banner: "SSH-2.0-af8ca74"

$ go-protocol-detector --format=jsonl --protocol=sftp --host=<github-ip> --port=22
# → negative, reason: "protocol_mismatch"
```

结论：`sftp` 报 hit 表示"已确认是 SFTP"；报 `protocol_mismatch` 表示"是 SSH 服务，
但无法在无凭据条件下确认 SFTP 子系统"。要凭据级确认，用下面的库 API
`CheckWithAuth`。

## CLI 用法

```bash
# 单个目标
go-protocol-detector --protocol=sftp --host=192.168.1.100 --port=22

# IP 范围 + 多端口
go-protocol-detector --protocol=sftp --host=192.168.1.1-254 --port=22,2222,8022

# 自定义线程和超时
go-protocol-detector --protocol=sftp --host=192.168.1.0/24 --port=22 --thread=20 --timeout=8000
```

注意：`--user` / `--password` / `--prikey` 对 `--protocol=sftp` 的扫描**不生效**——
CLI 扫描管线固定走上面的无凭据协议检测。凭据只在库 API（见下）里使用。

Agent 模式（stdout 非终端或 `--format=jsonl`）输出单行 JSONL 信封，
字段契约见 [AGENT_INSTRUCTION.md](./AGENT_INSTRUCTION.md)；负结果原因就是上表的三类。

## 库 API（Go）

### 带诊断信息的协议检测

```go
package main

import (
	"fmt"
	"time"

	"github.com/allanpk716/go-protocol-detector/internal/feature/sftp"
)

func main() {
	helper := sftp.NewSFTPHelper("192.168.1.100", "22", 10*time.Second)

	diag, err := helper.CheckWithDiagnostics()
	fmt.Printf("err: %v\n", err)
	fmt.Printf("TCP connected:    %v\n", diag.TCPConnected)
	fmt.Printf("SSH banner:       %s\n", diag.SSHBanner)
	fmt.Printf("SSH version:      %s\n", diag.SSHVersion)
	fmt.Printf("SFTP supported:   %v\n", diag.SFTPSupported)
	fmt.Printf("subsystem detail: %s\n", diag.SubsystemResponse)
	fmt.Printf("elapsed ms:       %d\n", diag.ElapsedTime)
	fmt.Printf("error msg:        %s\n", diag.ErrorMsg)
}
```

`err == nil` 即确认 SFTP；`diag` 无论成败都带每层的落地信息（第三层握手被拒时
`SubsystemResponse` 为 `SSH连接需要认证`）。

### 带凭据的确认式检测

真正可靠地确认一台需要认证的服务器，用 `CheckWithAuth`（用户名+密码，或私钥，
私钥可带口令）：

```go
err := helper.CheckWithAuth("username", "password", "")            // 密码
err = helper.CheckWithAuth("username", "key-passphrase", "~/.ssh/id_rsa") // 私钥
```

它完成完整的 SSH 登录并枚举根目录验证 SFTP 可用。未提供凭据时自动退回协议检测。

## 测试环境

```bash
# Docker 起一个本地 SFTP 服务器
docker run -d --name sftp-test-server -p 2222:22 atmoz/sftp testuser:testpass:::upload

# 无凭据协议检测（能否报 hit 取决于该镜像的认证配置）
go-protocol-detector --protocol=sftp --host=127.0.0.1 --port=2222

# 库 API 凭据确认（对上面这个镜像必定成功）
# helper.CheckWithAuth("testuser", "testpass", "")
```

## 排错建议

推荐排查顺序：`common`（端口通不通）→ `ssh`（是不是 SSH）→ `sftp`（子系统确认）。

| 现象 | 含义 | 建议 |
|---|---|---|
| `ssh` 命中、`sftp` 报 `protocol_mismatch` | 是 SSH，但无凭据握手过不了认证（最常见） | 需要确认就用库 API `CheckWithAuth` |
| `sftp` 全部 `timeout` | 网络慢或线程过多 | 加大 `--timeout`、降低 `--thread` |
| `sftp` 报 `closed` | 端口没开 | 先用 `--protocol=common` 验证 |
| banner 非 `SSH-` | 端口上是别的服务 | 换对应协议检测 |

## 历史变更说明

- 旧版策略"自动尝试常见弱凭据组合（admin:admin、demo:password 等）"已**移除**：
  未经授权的凭据尝试不符合协议检测器的定位，相关方法（`trySFTPWithCredentials`
  等）已从代码删除。
- 旧版诊断字段 `TCPOK` / `TriedUsers` / `SubsystemOK` / `TotalTime` 已不存在，
  现行字段见上文 `SFTPDiagnostics` 一节。
- `CheckWithAuth` 保留，作为用户提供凭据时的确认式检测。
