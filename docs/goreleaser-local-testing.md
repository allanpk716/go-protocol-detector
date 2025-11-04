# GoReleaser 本地测试指南

本文档提供了完整的 GoReleaser 本地测试流程，确保在不触发 GitHub Actions 的情况下验证构建和发布配置的正确性。

## 快速开始

### 日常开发验证
```bash
# 1. 验证配置文件语法
goreleaser check

# 2. 快速构建当前平台
goreleaser build --single-target --snapshot --rm-dist

# 3. 完整流程测试（不发布）
goreleaser release --snapshot --skip-publish --rm-dist
```

## 详细验证流程

### 第一阶段：配置验证

#### 1.1 检查配置文件语法
```bash
goreleaser check
```
**预期输出：**
```
• loading config file                              file=.goreleaser.yml
• checking config...
• config is valid
```

#### 1.2 检查环境状态
虽然没有直接的 `healthcheck` 命令，但可以通过以下方式验证环境：
```bash
# 检查 GoReleaser 版本
goreleaser --version

# 检查 Go 环境
go version

# 验证项目可以正常编译
go build ./cmd/go-protocol-detector
```

### 第二阶段：单平台构建测试

#### 2.1 Windows 平台构建
```bash
goreleaser build --id=windows-build --snapshot --rm-dist
```
**预期结果：**
- 构建文件：`dist/windows-build_windows_amd64_v1/go-protocol-detector.exe`
- 构建时间：约 2-5 秒
- 输出包含：`build succeeded after Xs`

#### 2.2 Linux AMD64 构建测试
```bash
# Windows CMD
set GOOS=linux && set GOARCH=amd64 && goreleaser build --id=linux-amd64-build --snapshot --rm-dist

# Windows PowerShell
$env:GOOS="linux"; $env:GOARCH="amd64"; goreleaser build --id=linux-amd64-build --snapshot --rm-dist
```
**预期结果：**
- 构建文件：`dist/linux-amd64-build_linux_amd64_v1/go-protocol-detector`
- 构建时间：约 8-12 秒（交叉编译较慢）

#### 2.3 Linux ARM64 构建测试
```bash
# Windows CMD
set GOOS=linux && set GOARCH=arm64 && goreleaser build --id=linux-arm64-build --snapshot --rm-dist

# Windows PowerShell
$env:GOOS="linux"; $env:GOARCH="arm64"; goreleaser build --id=linux-arm64-build --snapshot --rm-dist
```
**预期结果：**
- 构建文件：`dist/linux-arm64-build_linux_arm64/go-protocol-detector`
- 构建时间：约 8-12 秒

#### 2.4 Linux ARM v7 构建测试
```bash
# Windows CMD
set GOOS=linux && set GOARCH=arm && set GOARM=7 && goreleaser build --id=linux-armv7-build --snapshot --rm-dist

# Windows PowerShell
$env:GOOS="linux"; $env:GOARCH="arm"; $env:GOARM="7"; goreleaser build --id=linux-armv7-build --snapshot --rm-dist
```

### 第三阶段：完整构建测试

#### 3.1 所有平台构建
```bash
goreleaser build --snapshot --rm-dist
```
**预期结果：**
- 构建所有 4 个平台的二进制文件
- 总构建时间：约 10-15 秒
- 生成 `dist/artifacts.json` 和 `dist/metadata.json`

#### 3.2 完整发布流程测试
```bash
goreleaser release --snapshot --skip-publish --rm-dist
```
**预期结果：**
- 构建所有二进制文件
- 创建归档文件（.tar.gz）
- 生成 checksum 文件
- 跳过实际的 GitHub 发布

**预期生成的归档文件：**
- `dist/go-protocol-detector-vX.X.X-next-linux-amd64.tar.gz`
- `dist/go-protocol-detector-vX.X.X-next-linux-arm.tar.gz`
- `dist/go-protocol-detector-vX.X.X-next-linux-arm64.tar.gz`
- `dist/go-protocol-detector-vX.X.X-next-windows-amd64.tar.gz`
- `dist/checksums.txt`

## 命令参考手册

### build 命令参数
```bash
goreleaser build [flags]
```

**重要参数：**
- `--snapshot`: 生成无版本号的快照构建，跳过验证
- `--rm-dist`: 构建前清理 dist 目录
- `--single-target`: 仅构建当前 GOOS/GOARCH
- `--id stringArray`: 仅构建指定的构建 ID
- `--output string`: 构建后将二进制文件复制到指定路径（仅用于单目标构建）
- `--skip-before`: 跳过全局前置钩子
- `--skip-validate`: 跳过验证检查
- `--timeout duration`: 设置构建超时时间（默认 30m）

### release 命令参数
```bash
goreleaser release [flags]
```

**重要参数：**
- `--snapshot`: 生成快照发布（隐含 --skip-publish, --skip-announce, --skip-validate）
- `--skip-publish`: 跳过发布到 GitHub
- `--skip-announce`: 跳过发布公告
- `--skip-validate`: 跳过 git 检查
- `--skip-before`: 跳过全局前置钩子
- `--rm-dist`: 构建前清理 dist 目录
- `--auto-snapshot`: 如果仓库有未提交更改时自动启用快照模式
- `--timeout duration`: 设置发布超时时间（默认 30m）

## 测试场景和命令组合

### 日常开发场景
```bash
# 快速验证配置
goreleaser check

# 快速本地构建测试
goreleaser build --single-target --snapshot --rm-dist
```

### 发布前验证场景
```bash
# 1. 配置验证
goreleaser check

# 2. 单平台测试（根据当前系统）
goreleaser build --single-target --snapshot --rm-dist

# 3. 全平台构建测试
goreleaser build --snapshot --rm-dist

# 4. 完整流程测试
goreleaser release --snapshot --skip-publish --rm-dist
```

### 特定平台测试场景
```bash
# 仅测试 Windows 构建
goreleaser build --id=windows-build --snapshot --rm-dist

# 测试所有 Linux 平台
goreleaser build --id=linux-amd64-build --id=linux-armv7-build --id=linux-arm64-build --snapshot --rm-dist
```

### 性能测试场景
```bash
# 测试构建性能
time goreleaser build --snapshot --rm-dist

# 测试发布流程性能
time goreleaser release --snapshot --skip-publish --rm-dist
```

## 故障排查

### 常见错误及解决方案

#### 1. 配置文件错误
**错误：** `yaml: unmarshal errors`
**解决方案：**
```bash
# 检查配置文件语法
goreleaser check

# 检查 YAML 缩进和格式
# 确保使用空格而不是 Tab
```

#### 2. 构建失败
**错误：** `build failed`
**解决方案：**
```bash
# 检查 Go 模块
go mod tidy

# 验证代码可以编译
go build ./cmd/go-protocol-detector

# 检查依赖项
go mod verify
```

#### 3. 权限问题
**错误：** 权限拒绝或无法访问 GitHub
**解决方案：**
```bash
# 使用 --skip-publish 避免发布步骤
goreleaser release --snapshot --skip-publish --rm-dist

# 或设置 GitHub Token（如果需要）
set GITHUB_TOKEN=your_token_here
```

#### 4. 交叉编译失败
**错误：** 交叉编译目标平台构建失败
**解决方案：**
```bash
# 检查目标平台设置
echo %GOOS% %GOARCH%

# 确保使用正确的构建 ID
goreleaser build --help | findstr id
```

### 环境检查清单

在执行 GoReleaser 测试前，请确认：

- [ ] Go 版本符合要求（项目要求的版本）
- [ ] 项目代码可以正常编译：`go build ./cmd/go-protocol-detector`
- [ ] 依赖项已下载：`go mod download`
- [ ] Git 仓库状态正常（无未提交的重大更改，除非使用快照模式）
- [ ] 配置文件语法正确：`goreleaser check`
- [ ] 有足够的磁盘空间（建议至少 1GB 可用空间）

### 性能优化建议

1. **使用 --rm-dist**：确保每次都是干净构建，避免旧文件干扰
2. **并行构建**：GoReleaser 默认使用多核并行构建，无需额外配置
3. **本地缓存**：确保 Go 模块缓存正常，可以加速依赖下载
4. **SSD 硬盘**：使用 SSD 可以显著提升构建速度，特别是交叉编译

## 最佳实践

### 开发流程中的验证时机

1. **修改配置文件后**：运行 `goreleaser check`
2. **修改构建逻辑后**：运行 `goreleaser build --single-target --snapshot --rm-dist`
3. **提交代码前**：运行 `goreleaser build --snapshot --rm-dist`
4. **发布前**：运行完整的验证流程

### 发布前检查清单

在正式发布前，请完成以下检查：

- [ ] 配置文件验证通过：`goreleaser check`
- [ ] 所有目标平台构建成功
- [ ] 归档文件正确生成
- [ ] checksum 文件正确生成
- [ ] 版本号符合预期
- [ ] 构建的二进制文件可以正常运行

### CI/CD 集成注意事项

1. **本地测试优先**：在推送代码前先本地验证
2. **使用快照模式**：避免意外发布未验证的版本
3. **环境一致性**：确保本地和 CI 环境的 Go 版本一致
4. **权限管理**：CI 环境需要适当的 GitHub Token 权限

## 进阶用法

### 自定义构建测试
```bash
# 构建到指定目录
goreleaser build --single-target --snapshot --output ./build/myapp.exe

# 设置自定义超时时间
goreleaser release --snapshot --skip-publish --rm-dist --timeout=60m

# 使用自定义配置文件
goreleaser check --config ./my-goreleaser.yml
```

### 标签测试
```bash
# 创建测试标签
git tag v0.0.1-test

# 基于标签构建
goreleaser build --rm-dist

# 清理测试标签
git tag -d v0.0.1-test
```

### 调试模式
```bash
# 启用调试输出
goreleaser --debug release --snapshot --skip-publish --rm-dist
```

## 总结

通过遵循本指南的测试流程，您可以：

1. **确保配置正确**：避免 GitHub Actions 中的配置错误
2. **验证构建成功**：确保所有目标平台都能正常构建
3. **测试发布流程**：验证完整的发布和打包流程
4. **提高开发效率**：减少 CI/CD 中的错误和重试
5. **增强信心**：在发布前充分验证，确保发布质量

建议将此测试流程集成到您的开发工作流中，特别是在对 GoReleaser 配置或构建逻辑进行更改后。