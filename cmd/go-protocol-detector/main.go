package main

import (
	"fmt"
	"github.com/allanpk716/go-protocol-detector/pkg"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"strings"
	"time"
)

var (
	protocol string
	host     string
	port     string
	thread   int
	timeOut  int

	user           string
	password       string
	priKeyFullPath string
)

func main() {
	app := &cli.App{
		Name:        "go-protocol-detector",
		Usage:       "use like: go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389",
		Description: "Multi-protocol scan tool",
		Version:     "v0.1.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "protocol",
				Usage:       "select only one protocol: rdp | ssh | ftp | sftp | telnet | vnc | common",
				Value:       "common",
				Destination: &protocol,
			},
			&cli.StringFlag{
				Name:        "host",
				Value:       "192.168.1.1",
				Usage:       "support 3 diffs types: 192.168.1.1,192.168.1.100-254,192.168.1.0/24",
				Destination: &host,
			},
			&cli.StringFlag{
				Name:        "port",
				Value:       "22",
				Usage:       "support like: 22,80,443,3380-3390",
				Destination: &port,
			},
			&cli.IntFlag{
				Name:        "thread",
				Usage:       "10",
				Value:       10,
				Destination: &thread,
			},
			&cli.IntFlag{
				Name:        "timeout",
				Usage:       "1000 ms",
				Value:       1000,
				Destination: &timeOut,
			},
			&cli.StringFlag{
				Name:        "user",
				Usage:       "if you scan sftp, need give a UserName: root",
				Value:       "root",
				Destination: &user,
			},
			&cli.StringFlag{
				Name:        "password",
				Usage:       "if you scan sftp, need give a Password: root",
				Value:       "root",
				Destination: &password,
			},
			&cli.StringFlag{
				Name:        "prikey",
				Usage:       "if you scan sftp, need give a pri key Full Path( user name or this priKeyFPath only chose one): ~/.ssh/id_rsa",
				Value:       "~/.ssh/id_rsa",
				Destination: &priKeyFullPath,
			},
		},
		Action: func(c *cli.Context) error {

			nowProtocol := pkg.String2ProcotolType(protocol)

			outputInfo, err := pkg.NewScanTools(thread, time.Duration(timeOut)*time.Millisecond).Scan(nowProtocol, pkg.InputInfo{
				Host:               host,
				Port:               port,
				User:               user,
				Password:           password,
				PrivateKeyFullPath: priKeyFullPath,
			}, true)
			if err != nil {
				return err
			}

			println("==========================================================")
			info := protocol + " Scan Result: \r\n"
			for s2, i := range outputInfo.SuccessMapString {
				info += s2 + ":" + strings.Join(i, ",") + "\r\n"
			}
			fmt.Print(info)
			println("==========================================================")
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
