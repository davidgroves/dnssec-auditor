package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestFormatFindingComment(t *testing.T) {
	f := NewFinding(NSEC3Missing, Error, "ns1.nsec3-param.example.", dns.TypeNSEC3, "missing NSEC3")
	got := FormatFindingComment(f)
	want := "; NSEC3_MISSING ns1.nsec3-param.example. NSEC3 — missing NSEC3"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestErrorCommentsByOwner(t *testing.T) {
	findings := []Finding{
		NewFinding(NSEC3Missing, Error, "b.example.", dns.TypeNSEC3, "missing NSEC3"),
		NewFinding(RRSIGExpired, Error, "a.example.", dns.TypeA, "expired"),
		NewFinding(RRSIGExpiringSoon, Warning, "a.example.", dns.TypeA, "soon"),
	}
	got := ErrorCommentsByOwner(findings)
	if len(got) != 2 {
		t.Fatalf("want 2 owners, got %#v", got)
	}
	if len(got["a.example."]) != 1 || !strings.Contains(got["a.example."][0], "RRSIG_EXPIRED") {
		t.Fatalf("a.example. comments %#v", got["a.example."])
	}
	if _, ok := got["b.example."]; !ok {
		t.Fatal("missing b.example.")
	}
}
