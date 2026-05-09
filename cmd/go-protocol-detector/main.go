package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/allanpk716/ai-agent-cli-rules/sdks/go"
	"github.com/allanpk716/go-protocol-detector/pkg"
	"github.com/urfave/cli/v2"
)

var AppVersion = "unknown"

func main() {
	app := &cli.App{
		Name:        "go-protocol-detector",
		Usage:       "use like: go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389",
		Description: "Multi-protocol scan tool",
		Version:     AppVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "protocol",
				Usage: "select only one protocol: common | ftp | rdp | rustdesk-hbbs | rustdesk-hbbr | rustdesk-hbbs-21116 | sftp | ssh | telnet | vnc",
				Value: "common",
			},
			&cli.StringFlag{
				Name:  "host",
				Usage: "support 3 diffs types: 192.168.1.1,192.168.1.100-254,192.168.1.0/24",
			},
			&cli.StringFlag{
				Name:  "port",
				Usage: "support like: 22,80,443,3380-3390",
			},
			&cli.IntFlag{
				Name:  "thread",
				Usage: "10",
				Value: 10,
			},
			&cli.IntFlag{
				Name:  "timeout",
				Usage: "1000 ms",
				Value: 1000,
			},
			&cli.StringFlag{
				Name:  "user",
				Usage: "if you scan sftp, need give a UserName: root",
				Value: "root",
			},
			&cli.StringFlag{
				Name:  "password",
				Usage: "if you scan sftp, need give a Password: root",
				Value: "root",
			},
			&cli.StringFlag{
				Name:  "prikey",
				Usage: "if you scan sftp, need give a pri key Full Path( user name or this priKeyFPath only chose one): ~/.ssh/id_rsa",
				Value: "~/.ssh/id_rsa",
			},
			&cli.StringFlag{
				Name:  "csv-output",
				Usage: "output scan results to CSV file (specify file path to enable CSV output)",
				Value: "",
			},
			&cli.BoolFlag{
				Name:    "no-progress",
				Usage:   "disable progress bar output",
				Aliases: []string{"np"},
				Value:   false,
			},
			&cli.BoolFlag{
				Name:  "agent",
				Usage: "AI Agent mode, output JSONL format",
				Value: false,
			},
		},
		Action: func(c *cli.Context) error {
			// 检查是否没有任何参数被传递，如果没有则显示帮助信息
			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return nil
			}

			agentMode := c.Bool("agent")

			// Agent mode: initialize SDK App instance
			if agentMode {
				sdkApp := agentsdk.New("go-protocol-detector", AppVersion)
				log.Println("SDK App initialized:", sdkApp.Name(), "version:", sdkApp.Version())
				sdkApp.JSONL().Success(map[string]string{
					"mode":    "agent",
					"version": AppVersion,
				})
				log.Println("Agent mode enabled")
				return nil
			}

			// Human mode (default) — original logic, zero changes
			protocol := c.String("protocol")
			host := c.String("host")
			port := c.String("port")
			thread := c.Int("thread")
			timeOut := c.Int("timeout")
			user := c.String("user")
			password := c.String("password")
			priKeyFullPath := c.String("prikey")
			csvOutput := c.String("csv-output")
			noProgress := c.Bool("no-progress")

			nowProtocol := pkg.String2ProtocolType(protocol)
			scanTools := pkg.NewScanTools(thread, time.Duration(timeOut)*time.Millisecond)

			var outputInfo *pkg.OutputInfo
			var err error

			// Use ScanWithOutput for all scans (it supports progress bars)
			// showProgressStep = false to disable per-port logging (too verbose)
			// enableProgress = true to show progress bars (unless --no-progress flag is set)
			outputInfo, _, err = scanTools.ScanWithOutput(nowProtocol, pkg.InputInfo{
				Host:               host,
				Port:               port,
				User:               user,
				Password:           password,
				PrivateKeyFullPath: priKeyFullPath,
			}, false, csvOutput, !noProgress)

			if err != nil {
				return err
			}

			log.Println("==========================================================")
			info := protocol + " Scan Result: \n"

			// Show console output
			if outputInfo != nil {
				for s2, i := range outputInfo.SuccessMapString {
					info += s2 + ":" + strings.Join(i, ",") + "\n"
				}
			}

			if csvOutput != "" {
				info += fmt.Sprintf("CSV results saved to: %s\n", csvOutput)
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
