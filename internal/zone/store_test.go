package zone

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestAddRemoveSnapshot(t *testing.T) {
	st := NewStore("example.com.")
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.example.com.", Mbox: "h.example.com.", Serial: 5, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60}
	if err := st.AddRR(soa); err != nil {
		t.Fatal(err)
	}
	if st.Serial() != 5 {
		t.Fatalf("serial %d", st.Serial())
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 1}}
	if err := st.AddRR(a); err != nil {
		t.Fatal(err)
	}
	if st.RecordCount() != 2 {
		t.Fatalf("count %d", st.RecordCount())
	}
	var buf bytes.Buffer
	if err := st.WriteSnapshot(&buf); err != nil {
		t.Fatal(err)
	}
	st2, _, err := ReadSnapshot(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Serial() != 5 || st2.RecordCount() != 2 {
		t.Fatalf("snap serial=%d n=%d", st2.Serial(), st2.RecordCount())
	}
	if err := st.RemoveRR(a); err != nil {
		t.Fatal(err)
	}
	if st.Lookup("www.example.com.") != nil {
		t.Fatal("expected removed")
	}
}

func TestCanonicalCmp(t *testing.T) {
	if CanonicalCmp("example.com.", "example.com.") != 0 {
		t.Fatal("eq")
	}
	if CanonicalCmp("a.example.com.", "b.example.com.") >= 0 {
		t.Fatal("a < b")
	}
}

func TestSigningMode(t *testing.T) {
	st := NewStore("example.com.")
	if got := st.SigningMode(); got != SigningUnsigned {
		t.Fatalf("empty store: got %q", got)
	}

	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "www.example.com.",
		TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG},
	}
	if err := st.AddRR(nsec); err != nil {
		t.Fatal(err)
	}
	if got := st.SigningMode(); got != SigningNSEC {
		t.Fatalf("nsec only: got %q", got)
	}

	p := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0},
		Hash: dns.SHA1, Flags: 0, Iterations: 0, Salt: "-",
	}
	if err := st.AddRR(p); err != nil {
		t.Fatal(err)
	}
	if got := st.SigningMode(); got != SigningMixed {
		t.Fatalf("nsec+nsec3param: got %q", got)
	}

	st3 := NewStore("n3.example.")
	n3 := &dns.NSEC3{
		Hdr: dns.RR_Header{Name: "ABCDEF0123456789ABCDEF01234567.n3.example.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash: dns.SHA1, Flags: 1, Iterations: 0, Salt: "",
		NextDomain: "00000000000000000000000000000000",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}
	// HashLength/SaltLength required for in-memory NSEC3
	n3.HashLength = 20
	n3.SaltLength = 0
	if err := st3.AddRR(n3); err != nil {
		t.Fatal(err)
	}
	if got := st3.SigningMode(); got != SigningNSEC3 {
		t.Fatalf("nsec3 only: got %q", got)
	}
}

func TestWriteZoneFileAnnotated(t *testing.T) {
	st := NewStore("example.com.")
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns.example.com.", Mbox: "h.example.com.", Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60,
	}
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 1},
	}
	if err := st.AddRR(soa); err != nil {
		t.Fatal(err)
	}
	if err := st.AddRR(a); err != nil {
		t.Fatal(err)
	}
	comments := map[string][]string{
		"missing.example.com.": {"; NSEC3_MISSING missing.example.com. NSEC3 — missing NSEC3"},
		"www.example.com.":     {"; RRSIG_EXPIRED www.example.com. A — expired"},
	}
	var buf bytes.Buffer
	if err := st.WriteZoneFileAnnotated(&buf, comments); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "; RRSIG_EXPIRED www.example.com. A — expired\nwww.example.com.") {
		t.Fatalf("comment should precede owner RRs:\n%s", out)
	}
	if !strings.Contains(out, "; NSEC3_MISSING missing.example.com. NSEC3 — missing NSEC3\n") {
		t.Fatalf("orphan owner comment missing:\n%s", out)
	}
	missingIdx := strings.Index(out, "missing.example.com.")
	wwwIdx := strings.Index(out, "www.example.com.")
	if missingIdx < 0 || wwwIdx < 0 || missingIdx > wwwIdx {
		t.Fatalf("canonical order broken:\n%s", out)
	}
}
