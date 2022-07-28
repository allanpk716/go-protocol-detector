# Go Protocol Detector

[[中文]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn.md)

Network protocol detector. 

**Not Stable Version !** 

May be refactored in future use.

## Support Protocol

* RDP

* FTP

* SFTP

  > Something you should know, first, SSH validation is required, then check SFTP Client protocol.
  >
  > I think it need implemented by [gopacket](https://github.com/google/gopacket)

* SSH

* VNC

* Telnet

## How to use

### Use From Code:

* [detector_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/pkg/detector_test.go)
* [scan_tools_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/pkg/scan_tools_test.go)

### Use From Executable Program:

[Releases](https://github.com/allanpk716/go-protocol-detector/releases)

```powershell
go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389

go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389,1024-2000

go-protocol-detector --protocol=sftp --host=172.20.65.89-101 --port=3389 --user=root --password=123

go-protocol-detector --protocol=sftp --host=172.20.65.89-101 --port=3389 --password=123 --prikey=/keys/privatekey
```

## TODO

- [ ] SFTP detected by [gopacket](https://github.com/google/gopacket)

## How to implement

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn_tutorial.md)

## Thanks

* [ziutek/telnet](ziutek/telnet)