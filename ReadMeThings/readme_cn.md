# Go Protocol Detector

简易的网络协议的检测库。

> 还不是正式版本，可能在后续的使用中进行大方向的重构。建议观望下。
>

## 支持检测协议

* RDP

* FTP

* SFTP

  > SFTP（SSH 文件传输协议）运行在 SSH 协议之上，需要完整的 SSH 协议栈支持进行检测。
  >
  > 当前实现采用多层检测策略：无认证快速检测 → 常见凭据测试 → 高级检测模式。
  >
  > 由于 SSH 协议的加密特性，基于连接的检测是验证 SFTP 服务可用性的最可靠方法，数据包级别的检测因加密而不可行。

* SSH

* VNC

* Telnet

## 如何使用

看测试用例 [detector_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/detector_test.go)

## TODO

- [ ] 优化 SFTP 检测性能和凭据测试策略

## 如何实现的

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn_tutorial.md)

## 打赏

如果本人做的工具对你有一些帮助，可以请我喝一杯咖啡，或者赞助一点服务器费用。

![收款码](pics/收款码.png)

## 致谢

* [ziutek/telnet](ziutek/telnet)