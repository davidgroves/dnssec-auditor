package xfr

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

// Result is the outcome of a transfer.
type Result struct {
	Store    *zone.Store
	Adds     []dns.RR
	Removes  []dns.RR
	Method   string // axfr | ixfr
	Fallback bool   // IXFR answered with a full AXFR
	Serial   uint32
	Records  int
	Server   string
	Duration time.Duration
}

// SOAResult is a SOA probe outcome.
type SOAResult struct {
	Server    string
	Serial    uint32
	Refresh   uint32
	Retry     uint32
	Expire    uint32
	RTT       time.Duration
	Err       error
	Reachable bool
}

// Client talks to configured primaries.
type Client struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Client { return &Client{cfg: cfg} }

func (c *Client) tsigFor(server config.Server, zoneTSIG string) (map[string]string, string, string) {
	name := zoneTSIG
	if name == "" {
		name = server.TSIGKey
	}
	if name == "" {
		return nil, "", ""
	}
	k, ok := c.cfg.TSIGByName(name)
	if !ok {
		return nil, "", ""
	}
	keyName := dnsname.Canonical(k.Name)
	alg := tsigAlg(k.Algorithm)
	return map[string]string{keyName: k.Secret}, keyName, alg
}

func tsigAlg(name string) string {
	switch strings.ToLower(strings.TrimSuffix(name, ".")) {
	case "hmac-sha1", "hmac-sha1.":
		return dns.HmacSHA1
	case "hmac-sha256", "hmac-sha256.":
		return dns.HmacSHA256
	case "hmac-sha512", "hmac-sha512.":
		return dns.HmacSHA512
	case "hmac-sha384", "hmac-sha384.":
		return dns.HmacSHA384
	default:
		if name == "" {
			return dns.HmacSHA256
		}
		return name
	}
}

func (c *Client) addr(s config.Server) string {
	return net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
}

// ProbeSOA queries SOA at one server.
func (c *Client) ProbeSOA(ctx context.Context, zname string, server config.Server, zoneTSIG string, timeout time.Duration) SOAResult {
	start := time.Now()
	out := SOAResult{Server: server.Name}
	m := new(dns.Msg)
	m.SetQuestion(dnsname.Canonical(zname), dns.TypeSOA)
	cl := &dns.Client{Net: "udp", Timeout: timeout}
	secrets, keyName, alg := c.tsigFor(server, zoneTSIG)
	if secrets != nil {
		cl.TsigSecret = secrets
		m.SetTsig(keyName, alg, 300, time.Now().Unix())
	}
	r, _, err := cl.ExchangeContext(ctx, m, c.addr(server))
	if err != nil {
		// retry TCP
		cl.Net = "tcp"
		r, _, err = cl.ExchangeContext(ctx, m, c.addr(server))
	}
	out.RTT = time.Since(start)
	if err != nil {
		out.Err = err
		return out
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			out.Serial = soa.Serial
			out.Refresh = soa.Refresh
			out.Retry = soa.Retry
			out.Expire = soa.Expire
			out.Reachable = true
			return out
		}
	}
	out.Err = fmt.Errorf("no SOA in response")
	return out
}

// AXFR transfers a full zone.
func (c *Client) AXFR(ctx context.Context, zname string, server config.Server, zoneTSIG string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	zname = dnsname.Canonical(zname)
	t := new(dns.Transfer)
	t.DialTimeout = timeout
	t.ReadTimeout = timeout
	m := new(dns.Msg)
	m.SetAxfr(zname)
	secrets, keyName, alg := c.tsigFor(server, zoneTSIG)
	if secrets != nil {
		t.TsigSecret = secrets
		m.SetTsig(keyName, alg, 300, time.Now().Unix())
	}
	ch, err := t.In(m, c.addr(server))
	if err != nil {
		return nil, fmt.Errorf("axfr %s@%s: %w", zname, server.Name, err)
	}
	st := zone.NewStore(zname)
	n := 0
	for env := range ch {
		if env.Error != nil {
			return nil, fmt.Errorf("axfr %s@%s: %w", zname, server.Name, env.Error)
		}
		for _, rr := range env.RR {
			if rr.Header().Rrtype == dns.TypeTKEY {
				continue
			}
			if err := st.AddRR(rr); err != nil {
				return nil, err
			}
			n++
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return &Result{
		Store:    st,
		Method:   "axfr",
		Serial:   st.Serial(),
		Records:  n,
		Server:   server.Name,
		Duration: time.Since(start),
	}, nil
}

// IXFR requests an incremental transfer from fromSerial. If the server
// answers with a full zone (AXFR-style), Fallback is true and Store is set.
func (c *Client) IXFR(ctx context.Context, zname string, fromSerial uint32, server config.Server, zoneTSIG string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	zname = dnsname.Canonical(zname)
	t := new(dns.Transfer)
	t.DialTimeout = timeout
	t.ReadTimeout = timeout
	m := new(dns.Msg)
	m.SetIxfr(zname, fromSerial, "ns.", "hostmaster.")
	secrets, keyName, alg := c.tsigFor(server, zoneTSIG)
	if secrets != nil {
		t.TsigSecret = secrets
		m.SetTsig(keyName, alg, 300, time.Now().Unix())
	}
	ch, err := t.In(m, c.addr(server))
	if err != nil {
		return nil, fmt.Errorf("ixfr %s@%s: %w", zname, server.Name, err)
	}
	var all []dns.RR
	for env := range ch {
		if env.Error != nil {
			return nil, fmt.Errorf("ixfr %s@%s: %w", zname, server.Name, env.Error)
		}
		all = append(all, env.RR...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	adds, removes, serial, fallback := parseIXFR(all, fromSerial)
	res := &Result{
		Adds:     adds,
		Removes:  removes,
		Method:   "ixfr",
		Fallback: fallback,
		Serial:   serial,
		Records:  len(all),
		Server:   server.Name,
		Duration: time.Since(start),
	}
	if fallback {
		st, err := zone.FromAXFR(zname, stripSOAEnvelope(all))
		if err != nil {
			return nil, err
		}
		res.Store = st
		res.Method = "axfr"
		res.Serial = st.Serial()
		res.Records = st.RecordCount()
	}
	return res, nil
}

// parseIXFR interprets RFC 1995 responses.
// AXFR-style: SOA ... records ... SOA
// IXFR-style: SOA(new) [SOA(old) deleted... SOA(new) added...]+ SOA(new)
func parseIXFR(rrs []dns.RR, fromSerial uint32) (adds, removes []dns.RR, serial uint32, fallback bool) {
	var soas []*dns.SOA
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			soas = append(soas, soa)
		}
	}
	if len(soas) == 0 {
		return nil, nil, 0, true
	}
	serial = soas[0].Serial
	// A single pair of identical SOAs wrapping the whole zone is AXFR.
	if len(soas) == 2 && soas[0].Serial == soas[1].Serial {
		return nil, nil, serial, true
	}
	// More than two SOAs, or two with different serials: incremental.
	// Walk: first SOA is new serial. Then pairs of (old SOA + deletes + new SOA + adds).
	if len(soas) <= 2 && soas[0].Serial == fromSerial {
		// empty incremental (up to date)
		return nil, nil, serial, false
	}
	mode := 0 // 0 looking at first, 1 deleting, 2 adding
	for _, rr := range rrs {
		soa, isSOA := rr.(*dns.SOA)
		switch mode {
		case 0:
			if isSOA {
				mode = 1 // next section is deletes (old SOA)
			}
		case 1:
			if isSOA {
				if soa.Serial == serial {
					mode = 2
					adds = append(adds, soa)
				} else {
					removes = append(removes, soa)
				}
				continue
			}
			removes = append(removes, rr)
		case 2:
			if isSOA {
				if soa.Serial != serial {
					mode = 1
					removes = append(removes, soa)
					continue
				}
				// final SOA or next changeset start — ignore duplicate new SOA
				continue
			}
			adds = append(adds, rr)
		}
	}
	return adds, removes, serial, false
}

func stripSOAEnvelope(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := make([]dns.RR, 0, len(rrs))
	seenFirst := false
	for i, rr := range rrs {
		if _, ok := rr.(*dns.SOA); ok {
			if !seenFirst {
				out = append(out, rr)
				seenFirst = true
				continue
			}
			if i == len(rrs)-1 {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}
