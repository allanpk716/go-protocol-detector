# Go Protocol Detector

简易的网络协议的检测库。

> 还不是正式版本，可能在后续的使用中进行大方向的重构。建议观望下。
>

## 支持检测协议

* RDP

* FTP

* SFTP

  > SFTP（SSH 文件传输协议）运行在 SSH 协议之上，采用协议分析方式进行检测。
  >
  > 无需认证即可检测 SSH 服务和 SFTP 子系统的可用性。
  >
  > 快速三层检测：TCP连接 → SSH协议识别 → SFTP子系统查询。

* SSH

* VNC

* Telnet

* RustDesk

  > RustDesk 远程桌面软件检测。
  >
  > - **rustdesk-hbbs**：HBBS（信令/注册服务器）检测，端口 21116
  > - **rustdesk-hbbr**：HBBR（中继服务器）检测，端口 21117
  >
  > 基于 Protobuf 协议检测，可靠识别 RustDesk 服务器。

## 如何使用

看测试用例 [detector_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/detector_test.go)

### 命令行使用

```powershell
# RDP 扫描
go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389

# 快速 SFTP 检测（推荐，无需认证）
go-protocol-detector --protocol=sftp --host=172.20.65.1/24 --port=22

# SFTP 带认证检测（需要认证时使用）
go-protocol-detector --protocol=sftp --host=172.20.65.1/24 --port=22 --user=root --password=123

# RustDesk HBBS 信令服务器检测（端口 21116）
go-protocol-detector --protocol=rustdesk-hbbs --host=192.168.1.1-254 --port=21116

# RustDesk HBBR 中继服务器检测（端口 21117）
go-protocol-detector --protocol=rustdesk-hbbr --host=192.168.1.1-254 --port=21117
```

## TODO

- [ ] 优化 SFTP 检测性能和凭据测试策略

## 如何实现的

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn_tutorial.md)

## 打赏

如果本人做的工具对你有一些帮助，可以请我喝一杯咖啡，或者赞助一点服务器费用。

![收款码](pics/收款码.png)

## 致谢

* [ziutek/telnet](ziutek/telnet)