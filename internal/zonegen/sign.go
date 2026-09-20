package zonegen

import (
	"crypto"
	"fmt"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/miekg/dns"
)

func signZone(opt Options, rrs []dns.RR, ksk, zsk *dns.DNSKEY, kpriv, zpriv crypto.Signer) ([]dns.RR, error) {
	groups := map[string][]dns.RR{}
	key := func(name string, t uint16) string {
		return fmt.Sprintf("%s|%d", dnsname.Canonical(name), t)
	}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG {
			continue
		}
		k := key(h.Name, h.Rrtype)
		groups[k] = append(groups[k], rr)
	}
	out := append([]dns.RR{}, rrs...)
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		h := group[0].Header()
		// NS at a delegation cut is not signed.
		if h.Name != opt.Origin && h.Rrtype == dns.TypeNS {
			continue
		}
		// glue A/AAAA under a cut is not signed
		if isGlue(opt.Origin, groups, h.Name, h.Rrtype) {
			continue
		}
		signer := zpriv
		key := zsk
		if h.Rrtype == dns.TypeDNSKEY && dnsname.Canonical(h.Name) == opt.Origin {
			signer = kpriv
			key = ksk
		}
		sig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   h.Name,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    h.Ttl,
			},
			TypeCovered: h.Rrtype,
			Algorithm:   key.Algorithm,
			Labels:      uint8(dns.CountLabel(h.Name)),
			OrigTtl:     h.Ttl,
			Expiration:  opt.Expiration,
			Inception:   opt.Inception,
			KeyTag:      key.KeyTag(),
			SignerName:  key.Hdr.Name,
		}
		if err := sig.Sign(signer, group); err != nil {
			return nil, fmt.Errorf("sign %s/%s: %w", h.Name, dns.TypeToString[h.Rrtype], err)
		}
		out = append(out, sig)
	}
	return out, nil
}

func isGlue(origin string, groups map[string][]dns.RR, name string, rrtype uint16) bool {
	if rrtype != dns.TypeA && rrtype != dns.TypeAAAA {
		return false
	}
	name = dnsname.Canonical(name)
	if name == origin {
		return false
	}
	// if a parent (not origin) has NS, this is glue
	p := parent(name)
	for p != origin && p != "." {
		if _, ok := groups[fmt.Sprintf("%s|%d", p, dns.TypeNS)]; ok {
			return true
		}
		n := parent(p)
		if n == p {
			break
		}
		p = n
	}
	return false
}

func parent(name string) string {
	return dnsname.Parent(name)
}

// ResignRRSet signs one RRset with the given key and returns the RRSIG.
func ResignRRSet(rrs []dns.RR, key *dns.DNSKEY, priv crypto.Signer, inception, expiration uint32) (*dns.RRSIG, error) {
	if len(rrs) == 0 {
		return nil, fmt.Errorf("empty rrset")
	}
	h := rrs[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
		TypeCovered: h.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(h.Name)),
		OrigTtl:     h.Ttl,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
	}
	if err := sig.Sign(priv, rrs); err != nil {
		return nil, err
	}
	return sig, nil
}
