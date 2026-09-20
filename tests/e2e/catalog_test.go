//go:build e2e

package e2e

import (
	"testing"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/config"
	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
	"github.com/davidgroves/dnssec-auditor/tests/e2e/harness"
	"github.com/miekg/dns"
)

func TestCatalogMemberDiscovered(t *testing.T) {
	primary := testprimary.New()
	if err := primary.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(primary.Close)

	member, err := zonegen.Small("member.test.")
	if err != nil {
		t.Fatal(err)
	}
	primary.Load(member.Store)

	cat := zone.NewStore("catalog.example.")
	mustAdd(t, cat, &dns.SOA{
		Hdr: dns.RR_Header{Name: "catalog.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns.catalog.example.", Mbox: "hostmaster.catalog.example.",
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
	})
	mustAdd(t, cat, &dns.NS{Hdr: dns.RR_Header{Name: "catalog.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.catalog.example."})
	mustAdd(t, cat, &dns.TXT{Hdr: dns.RR_Header{Name: "version.catalog.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{"2"}})
	mustAdd(t, cat, &dns.PTR{Hdr: dns.RR_Header{Name: "abcd.zones.catalog.example.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600}, Ptr: "member.test."})
	primary.Load(cat)

	cfg := config.Defaults()
	cfg.API.Listen = harness.FreeListen()
	cfg.Notify.Enabled = false
	cfg.Refresh.MinInterval = config.Duration(time.Hour)
	cfg.Verification.Hygiene.Enabled = false
	cfg.Servers = []config.Server{{Name: "p1", Address: "127.0.0.1", Port: primary.Port}}
	cfg.Catalogs = []config.Catalog{
		{Name: "catalog.example.", Servers: []string{"p1"}, MemberServers: []string{"p1"}},
	}
	_, cli := harness.StartInProcess(t, cfg)
	harness.Eventually(t, 20*time.Second, func() bool {
		z, err := cli.Zone("member.test.")
		return err == nil && (z["state"] == "valid" || z["source"] == "catalog:catalog.example.")
	})
	z := harness.WaitState(t, cli, "member.test.", "valid", 30*time.Second)
	if src, _ := z["source"].(string); src != "catalog:catalog.example." {
		t.Fatalf("source %q", src)
	}
}

func mustAdd(t *testing.T, st *zone.Store, rr dns.RR) {
	t.Helper()
	if err := st.AddRR(rr); err != nil {
		t.Fatal(err)
	}
}
