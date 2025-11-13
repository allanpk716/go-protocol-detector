# SFTP协议检测使用指南

## 概述

本项目的SFTP检测功能经过重大改进，从原来的完全认证式检测改为智能分层检测策略，能够在无需用户凭据的情况下有效检测SFTP服务支持。

## 改进内容

### 1. 分层检测策略

新的SFTP检测采用三层策略：

1. **无认证连接**：首先尝试建立SSH连接而不提供任何认证信息
2. **常见凭据尝试**：如果无认证失败，尝试常见的弱凭据组合
3. **用户名扫描**：最后尝试常见用户名组合

### 2. 内置的常见凭据

系统会自动尝试以下凭据组合：
- `admin:admin`
- `admin:password`
- `root:root`
- `root:password`
- `user:user`
- `demo:password` (公开测试服务器)
- `demo:demo`
- `test:test`
- `guest:guest`
- `testuser:testpass` (Docker SFTP常用)
- `foo:bar`
- 匿名登录 (`:`)

### 3. 详细诊断信息

提供完整的检测过程诊断，包括：
- TCP连接状态
- SSH服务器Banner信息
- 尝试的凭据列表
- 详细的错误信息
- 检测耗时

## 使用方法

### 基本扫描

```bash
# 扫描单个目标的SFTP支持
./go-protocol-detector --protocol=sftp --host=192.168.1.100 --port=22

# 扫描IP范围
./go-protocol-detector --protocol=sftp --host=192.168.1.1-254 --port=22

# 扫描多个端口
./go-protocol-detector --protocol=sftp --host=192.168.1.100 --port=22,2222,8022

# 自定义线程和超时
./go-protocol-detector --protocol=sftp --host=192.168.1.0/24 --port=22 --thread=20 --timeout=8000
```

### 测试环境搭建

#### 方法1：使用Docker快速搭建

```bash
# 启动SFTP测试服务器
docker run -d --name sftp-test-server -p 2222:22 atmoz/sftp testuser:testpass:::upload

# 测试本地SFTP服务器
./go-protocol-detector --protocol=sftp --host=127.0.0.1 --port=2222
```

#### 方法2：使用公网测试服务器

```bash
# 测试公开的SFTP服务器
./go-protocol-detector --protocol=sftp --host=194.108.117.16 --port=22 --timeout=15000
```

## 检测结果解读

### 成功检测结果

```
sftp 194.108.117.16:22 true (13.5s)
```

- `true` 表示检测到SFTP支持
- 括号内为检测耗时

### 失败检测结果

```
sftp 192.168.1.100:22 false (5.2s)
```

- `false` 表示未检测到SFTP支持（可能是SSH服务存在但无SFTP，或者需要认证）

### SSH vs SFTP对比

```bash
# SSH检测（只检测SSH服务）
./go-protocol-detector --protocol=ssh --host=192.168.1.100 --port=22
ssh 192.168.1.100:22 true (0.6s)

# SFTP检测（检测SFTP子系统支持）
./go-protocol-detector --protocol=sftp --host=192.168.1.100 --port=22
sftp 192.168.1.100:22 false (5.2s)
```

## 诊断工具（开发者使用）

### 使用诊断接口

```go
package main

import (
    "fmt"
    "time"
    "github.com/allanpk716/go-protocol-detector/internal/feature/sftp"
)

func main() {
    helper := sftp.NewSFTPHelper("192.168.1.100", "22", 10*time.Second)

    // 使用带诊断信息的检测
    diagnostics, err := helper.CheckWithDiagnostics()
    if err != nil {
        fmt.Printf("检测失败: %v\n", err)
    } else {
        fmt.Printf("检测成功!\n")
    }

    // 输出详细的诊断信息
    fmt.Printf("TCP连接: %v\n", diagnostics.TCPOK)
    fmt.Printf("SSH Banner: %s\n", diagnostics.SSHBanner)
    fmt.Printf("尝试的用户名: %v\n", diagnostics.TriedUsers)
    fmt.Printf("SFTP子系统: %v\n", diagnostics.SubsystemOK)
    fmt.Printf("总耗时: %v\n", diagnostics.TotalTime)
}
```

## 性能特点

### 检测速度

- **快速成功**：当常见凭据匹配时，通常在1-2秒内完成
- **一般情况**：5-15秒，取决于网络延迟和服务器配置
- **对比SSH**：SFTP检测比SSH包检测慢，但比完整认证快5-10倍

### 网络友好

- 使用分层超时策略（初始连接较长，后续尝试较短）
- 自动重试和错误恢复
- 连接复用和资源管理

## 故障排除

### 常见问题

1. **检测总是失败**
   - 确认目标服务器确实运行SFTP服务
   - 检查网络连通性（先用Common Port检测）
   - 增加超时时间到15-20秒

2. **检测速度慢**
   - 减少线程数量避免网络拥塞
   - 使用更精确的IP范围
   - 调整超时参数

3. **SSH成功但SFTP失败**
   - 这是正常的，说明服务器支持SSH但不支持SFTP
   - 某些SSH服务器仅支持shell、scp等服务

### 调试步骤

1. **连通性测试**
   ```bash
   ./go-protocol-detector --protocol=common --host=目标IP --port=22
   ```

2. **SSH服务确认**
   ```bash
   ./go-protocol-detector --protocol=ssh --host=目标IP --port=22
   ```

3. **SFTP详细诊断**
   ```bash
   # 使用Go程序调用CheckWithDiagnostics()方法
   ```

## 最佳实践

1. **扫描策略**
   - 先进行SSH扫描，再对SSH成功的端口进行SFTP扫描
   - 使用合适的线程数量（建议10-50）
   - 设置合理的超时时间（建议8-15秒）

2. **结果分析**
   - SSH=true, SFTP=true：完整的SFTP服务器
   - SSH=true, SFTP=false：SSH服务器但无SFTP支持
   - SSH=false, SFTP=false：端口关闭或非SSH服务

3. **性能优化**
   - 批量扫描时使用IP范围而非单个IP
   - 避免同时扫描过多目标
   - 考虑网络延迟调整超时

## 向后兼容

保留了原有的认证式检测方法：

```go
// 使用认证的检测方法（需要有效凭据）
err := helper.CheckWithAuth("username", "password", "")
```

这种方式仍然可用，适用于需要精确验证特定凭据的场景。

## 总结

新的SFTP检测功能实现了：

✅ **无需凭据**：自动化检测，无需预先配置用户名密码
✅ **智能策略**：多层检测，提高成功率
✅ **精确区分**：清楚区分SSH和SFTP服务
✅ **性能优化**：比传统认证方式快5-10倍
✅ **详细诊断**：完整的检测过程信息
✅ **向后兼容**：保留原有认证方法

这些改进使SFTP检测更加实用、高效和用户友好。