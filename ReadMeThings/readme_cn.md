# Go Protocol Detector

简易的网络协议的检测库。

> 还不是正式版本，可能在后续的使用中进行大方向的重构。建议观望下。
>

## 支持检测协议

* RDP

* FTP

* SFTP

  > 这个检测很傻，因为优先做的是 SSH 的验证，才走的 FTP 的命令。然而在应用层又拿不到封包的特征，所以没啥用。
  >
  > 但是对于特殊应用场景也是能用的（逃
  >
  > 如果要做到合理的检测，就需要从这个 [gopacket](https://github.com/google/gopacket) 入手，有空再试试。doge

* SSH

* VNC

* Telnet

## 如何使用

看测试用例 [detector_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/detector_test.go)

## TODO

- [ ] SFTP detected by [gopacket](https://github.com/google/gopacket)

## 如何实现的

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn_tutorial.md)

## 打赏

如果本人做的工具对你有一些帮助，可以请我喝一杯咖啡，或者赞助一点服务器费用。

![收款码](pics/收款码.png)

## 致谢

* [ziutek/telnet](ziutek/telnet)