package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	agentsdk "github.com/allanpk716/ai-agent-cli-rules/sdks/go"
	scanErrors "github.com/allanpk716/go-protocol-detector/internal/errors"
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
		// OnUsageError covers flag parse failures (unknown flag, invalid value)
		// that urfave/cli raises BEFORE Action runs. In machine context
		// (stdout not a terminal) they must still produce one JSONL error
		// envelope with stderr silent and exit 2 — not a stderr text dump.
		OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
			if stdoutIsTerminal() {
				// Terminal: replicate urfave/cli's default usage-error output
				// ("Incorrect Usage." + app help), which our hook short-circuits.
				_, _ = fmt.Fprintf(c.App.Writer, "%s %s\n\n", "Incorrect Usage.", err.Error())
				_ = cli.ShowAppHelp(c)
				return err
			}
			w := newAgentWriter()
			_ = w.ErrorWithCode("INPUT_INVALID", err.Error())
			return cli.Exit("", agentsdk.ExitInvalidParams)
		},
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
			&cli.StringFlag{
				Name:  "format",
				Usage: "output format: auto | human | jsonl (explicit value always wins; unrecognized values fall back to auto)",
				Value: "auto",
			},
			&cli.BoolFlag{
				Name:  "agent",
				Usage: "prefer JSONL output (applies only when --format is auto/unrecognized)",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "output-file",
				Usage: "write full scan results (all negatives included, no truncation) as JSON to this file",
				Value: "",
			},
			&cli.BoolFlag{
				Name:  "self-describe",
				Usage: "print machine-readable capability description (JSONL when not human) and exit",
				Value: false,
			},
		},
		Action: func(c *cli.Context) error {
			// 检查是否没有任何参数被传递，如果没有则显示帮助信息
			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return nil
			}

			format := resolveFormat(c.String("format"), c.Bool("agent"), stdoutIsTerminal())

			// --self-describe: capability introspection, works in both formats
			if c.Bool("self-describe") {
				data := pkg.BuildSelfDescribeData(AppVersion)
				if format == "jsonl" {
					w := newAgentWriter()
					if err := pkg.EmitSelfDescribeEnvelope(w, data); err != nil {
						return cli.Exit(err.Error(), agentsdk.ExitFatalError)
					}
				} else {
					b, err := json.MarshalIndent(data, "", "  ")
					if err != nil {
						return cli.Exit(err.Error(), agentsdk.ExitFatalError)
					}
					fmt.Println(string(b))
				}
				return nil
			}

			if format == "jsonl" {
				return runAgentScan(c)
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
		if ec, ok := err.(cli.ExitCoder); ok {
			if ec.Error() != "" {
				fmt.Fprintln(os.Stderr, ec.Error())
			}
			os.Exit(ec.ExitCode())
		}
		log.Fatal(err)
	}
}

// newAgentWriter builds the JSONL writer on stdout. The SDK's NewWriter does
// NOT read AGENT_TRACE_ID (only App.New does — sdks/go@v0.2.0/writer.go:17),
// so we wire it here to honor the documented trace contract.
func newAgentWriter() *agentsdk.Writer {
	w := agentsdk.NewWriter(os.Stdout, "go-protocol-detector")
	if tid := os.Getenv("AGENT_TRACE_ID"); tid != "" {
		w.SetTraceID(tid)
	}
	return w
}

// resolveFormat decides the output mode.
// Rule (single source of truth, mirrored by TestResolveFormat):
//  1. an explicit --format=human|jsonl ALWAYS wins;
//  2. otherwise --agent forces jsonl;
//  3. otherwise TTY detection — this is also where unrecognized --format
//     values land (documented fallback, not an error).
func resolveFormat(format string, agentFlag bool, stdoutIsTTY bool) string {
	switch format {
	case "human", "jsonl":
		return format
	}
	if agentFlag {
		return "jsonl"
	}
	if stdoutIsTTY {
		return "human"
	}
	return "jsonl"
}

// stdoutIsTerminal reports whether stdout is a character device.
// Note: redirecting to NUL on Windows also looks like a char device — acceptable.
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// classifyExitError maps an error to (exit code, envelope error_code).
// Validation and resource-limit errors are input problems (exit 2); anything
// else is internal (exit 1).
func classifyExitError(err error) (int, string) {
	var se *scanErrors.ScannerError
	if errors.As(err, &se) &&
		(se.Type == scanErrors.ErrorTypeValidation || se.Type == scanErrors.ErrorTypeResourceLimit) {
		return agentsdk.ExitInvalidParams, "INPUT_INVALID"
	}
	return agentsdk.ExitFatalError, "INTERNAL_ERROR"
}

// runAgentScan executes the scan in agent (JSONL) mode: stderr silent unless
// AGENT_DEBUG=1, single result envelope, semantic exit codes.
func runAgentScan(c *cli.Context) error {
	w := newAgentWriter()

	if os.Getenv("AGENT_DEBUG") == "" {
		log.SetOutput(io.Discard)
	}

	defer func() {
		if r := recover(); r != nil {
			stackBuf := make([]byte, 4096)
			n := runtime.Stack(stackBuf, false)
			_ = w.ErrorWithCode("FATAL_CRASH", fmt.Sprintf("panic: %v\nStack:\n%s", r, stackBuf[:n]))
			os.Exit(agentsdk.ExitFatalError)
		}
	}()

	protocolName := c.String("protocol")
	if !pkg.IsKnownProtocol(protocolName) {
		_ = w.ErrorWithCode("INPUT_INVALID", fmt.Sprintf("unknown protocol: %q", protocolName))
		return cli.Exit("", agentsdk.ExitInvalidParams)
	}
	host := c.String("host")
	port := c.String("port")
	if host == "" || port == "" {
		_ = w.ErrorWithCode("INPUT_INVALID", "both --host and --port are required")
		return cli.Exit("", agentsdk.ExitInvalidParams)
	}

	nowProtocol := pkg.String2ProtocolType(protocolName)
	scanTools := pkg.NewScanTools(c.Int("thread"), time.Duration(c.Int("timeout"))*time.Millisecond)

	outputInfo, scanContext, err := scanTools.ScanWithOutput(nowProtocol, pkg.InputInfo{
		Host:               host,
		Port:               port,
		User:               c.String("user"),
		Password:           c.String("password"),
		PrivateKeyFullPath: c.String("prikey"),
	}, false, "", false)
	if err != nil {
		code, errCode := classifyExitError(err)
		_ = w.ErrorWithCode(errCode, err.Error())
		return cli.Exit("", code)
	}

	outputFile := c.String("output-file")
	report := pkg.BuildAgentReport(
		nowProtocol.String(),
		scanContext.ScanID,
		outputInfo.AllResults,
		scanContext.HostsCount,
		scanContext.PortsCount,
		scanContext.GetElapsedDuration().Milliseconds(),
		pkg.DefaultSampleLimit,
		outputFile,
	)

	if outputFile != "" {
		if err := pkg.WriteFullResultsJSON(outputFile, nowProtocol.String(), scanContext.ScanID, outputInfo.AllResults); err != nil {
			_ = w.ErrorWithCode("INTERNAL_ERROR", fmt.Sprintf("failed to write output file: %v", err))
			return cli.Exit("", agentsdk.ExitFatalError)
		}
	}

	if err := pkg.EmitScanResultEnvelope(w, report); err != nil {
		return cli.Exit(err.Error(), agentsdk.ExitFatalError)
	}

	// Conservative NETWORK_ERROR: scan completed but nothing was reachable at all
	if pkg.IsAllUnreachable(report) {
		return cli.Exit("", agentsdk.ExitNetworkError)
	}
	return nil
}
