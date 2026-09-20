package zone

import (
	"testing"

	"github.com/miekg/dns"
)

func TestPackRoundTripNSEC(t *testing.T) {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "www.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	rd, err := PackRR(nsec)
	if err != nil {
		t.Fatal(err)
	}
	back, err := unpackOne("example.com.", dns.TypeNSEC, 3600, rd)
	if err != nil {
		t.Fatal(err)
	}
	if back.String() != nsec.String() {
		t.Fatalf("\nwant %s\n got %s", nsec.String(), back.String())
	}
}

func TestPackRoundTripNSEC3(t *testing.T) {
	n3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: "0123456789abcdef0123456789abcdef.example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       dns.SHA1,
		Flags:      1,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "-",
		HashLength: 20,
		NextDomain: "0123456789ABCDEF0123456789ABCDEF",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM},
	}
	rd, err := PackRR(n3)
	if err != nil {
		t.Fatal(err)
	}
	back, err := unpackOne(n3.Hdr.Name, dns.TypeNSEC3, 3600, rd)
	if err != nil {
		t.Fatal(err)
	}
	if back.String() != n3.String() {
		t.Fatalf("\nwant %s\n got %s", n3.String(), back.String())
	}
}
