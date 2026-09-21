package main

import (
	"fmt"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/testprimary"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
	"github.com/miekg/dns"
)

func loadExamplePack(s *testprimary.Server) error {
	extras := []zonegen.ExampleSpec{
		{
			Origin:  "example.com.",
			Options: zonegen.Options{Origin: "example.com.", Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 1},
		},
		{
			Origin:  "nsec.example.",
			Options: zonegen.Options{Origin: "nsec.example.", Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC, Seed: 2},
		},
		{
			Origin:  "unsigned.example.",
			Options: zonegen.Options{Origin: "unsigned.example.", Delegations: 0, Denial: zonegen.DenialNone, Seed: 3},
		},
		{
			Origin:  "broken.example.",
			Options: zonegen.Options{Origin: "broken.example.", Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 4},
			Mutate:  zonegen.FlipRRSIG,
		},
		{
			Origin:  "member.example.",
			Options: zonegen.Options{Origin: "member.example.", Delegations: 4, SecurePct: 50, Denial: zonegen.DenialNSEC3OptOut, Seed: 5},
		},
	}
	var members []string
	for _, spec := range append(extras, zonegen.ExamplePack()...) {
		if spec.Options.Origin == "" {
			spec.Options.Origin = spec.Origin
		}
		g, err := zonegen.GenerateExample(spec)
		if err != nil {
			return err
		}
		s.Load(g.Store)
		members = append(members, spec.Origin)
		fmt.Printf("loaded %s\n", spec.Origin)
	}
	if err := loadCatalog(s, members); err != nil {
		return err
	}
	fmt.Println("loaded catalog.example.")
	return nil
}

func loadCatalog(s *testprimary.Server, members []string) error {
	origin := "catalog.example."
	st := zone.NewStore(origin)
	add := func(rr dns.RR) error { return st.AddRR(rr) }
	if err := add(&dns.SOA{
		Hdr:     dns.RR_Header{Name: origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns." + origin,
		Mbox:    "hostmaster." + origin,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}); err != nil {
		return err
	}
	if err := add(&dns.NS{
		Hdr: dns.RR_Header{Name: origin, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "invalid.",
	}); err != nil {
		return err
	}
	if err := add(&dns.TXT{
		Hdr: dns.RR_Header{Name: "version." + origin, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"2"},
	}); err != nil {
		return err
	}
	for _, m := range members {
		label := strings.ReplaceAll(strings.TrimSuffix(m, "."), ".", "-")
		if err := add(&dns.PTR{
			Hdr: dns.RR_Header{Name: label + ".zones." + origin, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600},
			Ptr: m,
		}); err != nil {
			return err
		}
	}
	s.Load(st)
	return nil
}
