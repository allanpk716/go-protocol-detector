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
	csvOutput      string
)

var AppVersion = "unknow"

func main() {
	app := &cli.App{
		Name:        "go-protocol-detector",
		Usage:       "use like: go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389",
		Description: "Multi-protocol scan tool",
		Version:     AppVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "protocol",
				Usage:       "select only one protocol: common | ftp | rdp | rustdesk-hbbs | rustdesk-hbbr | rustdesk-hbbs-21116 | sftp | ssh | telnet | vnc",
				Value:       "common",
				Destination: &protocol,
			},
			&cli.StringFlag{
				Name:        "host",
				Usage:       "support 3 diffs types: 192.168.1.1,192.168.1.100-254,192.168.1.0/24",
				Destination: &host,
			},
			&cli.StringFlag{
				Name:        "port",
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
			&cli.StringFlag{
				Name:        "csv-output",
				Usage:       "output scan results to CSV file (specify file path to enable CSV output)",
				Value:       "",
				Destination: &csvOutput,
			},
			&cli.BoolFlag{
				Name:    "no-progress",
				Usage:   "disable progress bar output",
				Aliases: []string{"np"},
				Value:   false,
			},
		},
		Action: func(c *cli.Context) error {
			// 检查是否没有任何参数被传递，如果没有则显示帮助信息
			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return nil
			}

			nowProtocol := pkg.String2ProtocolType(protocol)
			scanTools := pkg.NewScanTools(thread, time.Duration(timeOut)*time.Millisecond)

			var outputInfo *pkg.OutputInfo
			var err error

			// Check if CSV output is enabled (only when --csv-output is specified)
			if csvOutput != "" {
				// Use ScanWithOutput for CSV output
				outputInfo, _, err = scanTools.ScanWithOutput(nowProtocol, pkg.InputInfo{
					Host:               host,
					Port:               port,
					User:               user,
					Password:           password,
					PrivateKeyFullPath: priKeyFullPath,
				}, true, csvOutput, !c.Bool("no-progress"))
			} else {
				// Don't save to CSV, just scan and show console output
				outputInfo, err = scanTools.Scan(nowProtocol, pkg.InputInfo{
					Host:               host,
					Port:               port,
					User:               user,
					Password:           password,
					PrivateKeyFullPath: priKeyFullPath,
				}, true)
			}

			if err != nil {
				return err
			}

			log.Println("==========================================================")
			info := protocol + " Scan Result: \r\n"

			// Show console output
			if outputInfo != nil {
				for s2, i := range outputInfo.SuccessMapString {
					info += s2 + ":" + strings.Join(i, ",") + "\r\n"
				}
			}

			if csvOutput != "" {
				info += fmt.Sprintf("CSV results saved to: %s\r\n", csvOutput)
			}

			fmt.Print(info)
			log.Println("==========================================================")
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
