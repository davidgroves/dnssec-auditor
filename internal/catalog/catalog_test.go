package catalog

import (
	"testing"

	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

func TestParseCatalog(t *testing.T) {
	st := zone.NewStore("catalog.example.")
	mustAdd(t, st, &dns.SOA{Hdr: dns.RR_Header{Name: "catalog.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.", Mbox: "m.", Serial: 1})
	mustAdd(t, st, &dns.TXT{Hdr: dns.RR_Header{Name: "version.catalog.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{"2"}})
	mustAdd(t, st, &dns.PTR{Hdr: dns.RR_Header{Name: "1234.zones.catalog.example.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600}, Ptr: "member.test."})
	mustAdd(t, st, &dns.TXT{Hdr: dns.RR_Header{Name: "group.1234.zones.catalog.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{"g1"}})
	ver, members, err := Parse(st)
	if err != nil {
		t.Fatal(err)
	}
	if ver != "2" {
		t.Fatalf("version %q", ver)
	}
	if len(members) != 1 || members[0].Zone != "member.test." || members[0].Group != "g1" {
		t.Fatalf("%+v", members)
	}
	added, removed := Diff(nil, members)
	if len(added) != 1 || len(removed) != 0 {
		t.Fatalf("diff %v %v", added, removed)
	}
}

func mustAdd(t *testing.T, st *zone.Store, rr dns.RR) {
	t.Helper()
	if err := st.AddRR(rr); err != nil {
		t.Fatal(err)
	}
}
