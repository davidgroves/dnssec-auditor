package check

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/xfr"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

type Options struct {
	Zone   string
	File   string
	AXFR   string
	TSIG   string // name:alg:secret
	Time   time.Time
	ZONEMD string
	JSON   bool
}

func Run(opt Options, w io.Writer) int {
	if w == nil {
		w = os.Stdout
	}
	if opt.Zone == "" {
		fmt.Fprintln(os.Stderr, "check: --zone is required")
		return 1
	}
	opt.Zone = dnsname.Canonical(opt.Zone)
	var st *zone.Store
	var err error
	switch {
	case opt.File != "":
		st, err = fromFile(opt.Zone, opt.File)
	case opt.AXFR != "":
		st, err = fromAXFR(opt.Zone, opt.AXFR, opt.TSIG)
	default:
		fmt.Fprintln(os.Stderr, "check: --file or --axfr is required")
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "check: load zone: %v\n", err)
		return 1
	}
	cfg := config.Defaults().Verification
	if opt.ZONEMD != "" {
		cfg.ZONEMD = opt.ZONEMD
	}
	v := dnssec.New(cfg)
	if !opt.Time.IsZero() {
		t := opt.Time
		v.WithNow(func() time.Time { return t })
	}
	res := v.Full(st)
	if opt.JSON {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"zone":     opt.Zone,
			"valid":    res.Valid,
			"unsigned": res.Unsigned,
			"findings": res.Findings.List(),
		})
	} else {
		state := "VALID"
		if res.Unsigned {
			state = "UNSIGNED"
		} else if !res.Valid {
			state = "INVALID"
		}
		fmt.Fprintf(w, "%s %s  findings=%d errors=%d warnings=%d\n",
			opt.Zone, state, res.Findings.Len(),
			res.Findings.CountBySeverity(dnssec.Error),
			res.Findings.CountBySeverity(dnssec.Warning))
		for _, f := range res.Findings.List() {
			fmt.Fprintf(w, "  %-8s %-24s %s %s  %s\n", f.Severity, f.Code, f.Owner, f.RRTypeName, f.Message)
		}
	}
	if res.Findings.HasErrors() {
		return 1
	}
	if res.Findings.CountBySeverity(dnssec.Warning) > 0 {
		return 2
	}
	return 0
}

func fromFile(origin, path string) (*zone.Store, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zp := dns.NewZoneParser(f, origin, path)
	st := zone.NewStore(origin)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := st.AddRR(rr); err != nil {
			return nil, err
		}
	}
	return st, zp.Err()
}

func fromAXFR(origin, addr, tsig string) (*zone.Store, error) {
	cfg := config.Defaults()
	host, port := addr, 53
	if h, p, err := splitHostPort(addr); err == nil {
		host, port = h, p
	}
	srv := config.Server{Name: "cli", Address: host, Port: port}
	if tsig != "" {
		name, alg, secret := parseTSIG(tsig)
		cfg.TSIGKeys = []config.TSIGKey{{Name: name, Algorithm: alg, Secret: secret}}
		srv.TSIGKey = name
	}
	c := xfr.New(&cfg)
	res, err := c.AXFR(context.Background(), origin, srv, srv.TSIGKey, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	return res.Store, nil
}

func splitHostPort(s string) (string, int, error) {
	var host, portS string
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			host, portS = s[:i], s[i+1:]
			break
		}
	}
	if portS == "" {
		return "", 0, fmt.Errorf("no port")
	}
	var p int
	_, err := fmt.Sscanf(portS, "%d", &p)
	return host, p, err
}

func parseTSIG(s string) (name, alg, secret string) {
	parts := split3(s)
	return parts[0], parts[1], parts[2]
}

func split3(s string) [3]string {
	var out [3]string
	i, start := 0, 0
	for n := 0; n < 2 && i < len(s); i++ {
		if s[i] == ':' {
			out[n] = s[start:i]
			start = i + 1
			n++
		}
	}
	out[2] = s[start:]
	return out
}
