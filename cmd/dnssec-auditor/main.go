package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/app"
	"github.com/davidgroves/dnssec-auditor/internal/check"
	"github.com/davidgroves/dnssec-auditor/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "serve")
	}
	cmd := os.Args[1]
	// default: treat unknown first arg starting with - as serve flags
	if len(os.Args) >= 2 && os.Args[1] != "" && os.Args[1][0] == '-' {
		cmd = "serve"
		os.Args = append([]string{os.Args[0], "serve"}, os.Args[1:]...)
	}
	switch cmd {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		cfg := fs.String("config", "", "path to YAML config file")
		fs.Parse(os.Args[2:])
		if err := app.Serve(*cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "check":
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		zone := fs.String("zone", "", "zone origin")
		file := fs.String("file", "", "zone file")
		axfr := fs.String("axfr", "", "AXFR server host:port")
		tsig := fs.String("tsig", "", "TSIG name:alg:secret")
		when := fs.String("time", "", "RFC3339 validation time")
		zonemd := fs.String("zonemd", "", "auto|on|off")
		asJSON := fs.Bool("json", false, "JSON output")
		fs.Parse(os.Args[2:])
		opt := check.Options{Zone: *zone, File: *file, AXFR: *axfr, TSIG: *tsig, ZONEMD: *zonemd, JSON: *asJSON}
		if *when != "" {
			t, err := time.Parse(time.RFC3339, *when)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			opt.Time = t
		}
		os.Exit(check.Run(opt, os.Stdout))
	case "version", "-version", "--version":
		fmt.Printf("dnssec-auditor %s commit=%s built=%s\n", version.Version, version.Commit, version.BuildTime)
	case "help", "-h", "--help":
		fmt.Print(`dnssec-auditor — DNSSEC zone auditor

Usage:
  dnssec-auditor serve  --config FILE
  dnssec-auditor check  --zone NAME (--file FILE | --axfr HOST:PORT) [--tsig name:alg:secret] [--time RFC3339] [--zonemd auto|on|off] [--json]
  dnssec-auditor version
`)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}
