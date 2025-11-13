# Go Protocol Detector

[[中文]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn.md)

Network protocol detector. 

**Not Stable Version !** 

May be refactored in future use.

## Support Protocol

* RDP

* FTP

* SFTP

  > SFTP (SSH File Transfer Protocol) detection using protocol analysis.
  >
  > Detects SSH service and SFTP subsystem availability without authentication.
  >
  > Fast 3-layer detection: TCP connection → SSH protocol identification → SFTP subsystem query.

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
NAME:
   go-protocol-detector - use like: go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389

USAGE:
   go-protocol-detector [global options] command [command options] [arguments...]

VERSION:
   v0.10.0

DESCRIPTION:
   Multi-protocol scan tool

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h        show help (default: false)
   --host value      support 3 diffs types: 192.168.1.1,192.168.1.100-254,192.168.1.0/24 (default: "192.168.1.1")
   --password value  if you scan sftp, need give a Password: root (default: "root")
   --port value      support like: 22,80,443,3380-3390 (default: "22")
   --prikey value    if you scan sftp, need give a pri key Full Path( user name or this priKeyFPath only chose one): ~/.ssh/id_rsa (default: "~/.ssh/id_rsa")
   --protocol value  select only one protocol: rdp | ssh | ftp | sftp | telnet | vnc | common (default: "common")
   --thread value    10 (default: 10)
   --timeout value   1000 ms (default: 1000)
   --user value      if you scan sftp, need give a UserName: root (default: "root")
   --version, -v     print the version (default: false)
```

Example:

```powershell
go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389

go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389,1024-2000

# Fast SFTP detection (recommended, no authentication required)
go-protocol-detector --protocol=sftp --host=172.20.65.1/24 --port=22

# SFTP detection with authentication (when required)
go-protocol-detector --protocol=sftp --host=172.20.65.1/24 --port=22 --user=root --password=123
```

## TODO

- [ ] Optimize SFTP detection performance and credential testing strategy

## Give a reward

If the tools I have made are of some help to you, you can buy me a cup of coffee or sponsor a little server fee.

![收款码](ReadMeThings/pics/收款码.png)

## How to implement

[[中文教程]](https://github.com/allanpk716/go-protocol-detector/blob/master/ReadMeThings/readme_cn_tutorial.md)

## Thanks

* [ziutek/telnet](ziutek/telnet)