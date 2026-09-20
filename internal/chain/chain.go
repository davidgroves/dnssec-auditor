package chain

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/event"
	"github.com/davidgroves/dnssec-auditor/internal/metrics"
	"github.com/davidgroves/dnssec-auditor/internal/monitor"
	"github.com/miekg/dns"
)

type Checker struct {
	cfg     config.ChainConfig
	metrics *metrics.Metrics
	bus     *event.Bus
}

func New(cfg config.ChainConfig, m *metrics.Metrics, bus *event.Bus) *Checker {
	return &Checker{cfg: cfg, metrics: m, bus: bus}
}

type Result struct {
	OK       bool
	Insecure bool
	Matched  []uint16
	ParentDS []*dns.DS
	Err      error
}

func (c *Checker) Check(ctx context.Context, z *monitor.ZoneRuntime) Result {
	if !c.cfg.Enabled {
		return Result{OK: true}
	}
	st, _ := z.StoreAndChain()
	origin := z.Name
	if st == nil {
		return Result{Err: fmt.Errorf("no store")}
	}
	keys, err := st.DNSKEYs()
	if err != nil || len(keys) == 0 {
		return Result{Insecure: true, OK: true}
	}
	dsset, err := c.lookupDS(ctx, origin)
	if err != nil {
		return Result{Err: err}
	}
	if len(dsset) == 0 {
		f := dnssec.NewFinding(dnssec.InsecureDelegation, dnssec.Warning, origin, dns.TypeDS, "parent has no DS")
		ok := true
		z.ApplyFindings([]dnssec.Finding{f}, &ok, false)
		c.metrics.ZoneChainOK.WithLabelValues(origin).Set(1)
		return Result{Insecure: true, OK: true}
	}
	matched := []uint16{}
	for _, k := range keys {
		if k.Flags&dns.SEP == 0 {
			continue
		}
		for _, digest := range []uint8{dns.SHA256, dns.SHA1, dns.SHA384} {
			ds := k.ToDS(digest)
			if ds == nil {
				continue
			}
			for _, p := range dsset {
				if p.KeyTag == ds.KeyTag && p.Algorithm == ds.Algorithm && p.DigestType == ds.DigestType && equalFold(p.Digest, ds.Digest) {
					matched = append(matched, k.KeyTag())
				}
			}
		}
	}
	res := Result{ParentDS: dsset, Matched: matched, OK: len(matched) > 0}
	ok := res.OK
	var findings []dnssec.Finding
	if !res.OK {
		code := dnssec.DSMismatch
		if len(dsset) == 0 {
			code = dnssec.DSMissing
		}
		sev := dnssec.Error
		if !c.cfg.RequireMatch {
			sev = dnssec.Warning
		}
		findings = append(findings, dnssec.NewFinding(code, sev, origin, dns.TypeDS, "no DNSKEY matches parent DS"))
	}
	z.ApplyFindings(findings, &ok, !res.OK && c.cfg.RequireMatch)
	val := 0.0
	if res.OK {
		val = 1
	}
	c.metrics.ZoneChainOK.WithLabelValues(origin).Set(val)
	if !res.OK {
		c.bus.Publish(event.Event{Type: event.ChainOfTrustFailed, Zone: origin})
	}
	return res
}

func (c *Checker) lookupDS(ctx context.Context, zone string) ([]*dns.DS, error) {
	m := new(dns.Msg)
	m.SetQuestion(dnsname.Canonical(zone), dns.TypeDS)
	m.SetEdns0(4096, true)
	m.CheckingDisabled = true
	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	var last error
	targets := c.cfg.Resolvers
	if c.cfg.Mode == "authoritative" {
		parent := dnsname.Parent(zone)
		ns, err := lookupNS(parent)
		if err != nil {
			return nil, err
		}
		targets = ns
	}
	for _, t := range targets {
		if _, _, err := net.SplitHostPort(t); err != nil {
			t = net.JoinHostPort(t, "53")
		}
		r, _, err := cl.ExchangeContext(ctx, m, t)
		if err != nil {
			last = err
			continue
		}
		var out []*dns.DS
		for _, rr := range r.Answer {
			if ds, ok := rr.(*dns.DS); ok {
				out = append(out, ds)
			}
		}
		return out, nil
	}
	if last == nil {
		last = fmt.Errorf("no resolvers")
	}
	return nil, last
}

func lookupNS(zone string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dnsname.Canonical(zone), dns.TypeNS)
	cl := &dns.Client{Timeout: 5 * time.Second}
	r, _, err := cl.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range r.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, ns.Ns+":53")
		}
	}
	return out, nil
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'F' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'F' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func (c *Checker) Run(ctx context.Context, mgr *monitor.Manager) {
	if !c.cfg.Enabled {
		return
	}
	t := time.NewTicker(c.cfg.Interval.Duration())
	if c.cfg.Interval.Duration() <= 0 {
		t.Stop()
		return
	}
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, z := range mgr.List() {
				c.Check(ctx, z)
			}
		}
	}
}
