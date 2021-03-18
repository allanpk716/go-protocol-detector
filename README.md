# Go Protocol Detector

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

See [detector_test.go](https://github.com/allanpk716/go-protocol-detector/blob/master/detector_test.go)

## TODO

- [ ] SFTP detected by [gopacket](https://github.com/google/gopacket)

## How to implement

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn.md)

## Thanks

* [ziutek/telnet](ziutek/telnet)