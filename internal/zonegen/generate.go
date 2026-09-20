package zonegen

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/davidgroves/dnssec-auditor/internal/dnssec"
	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

type Denial string

const (
	DenialNSEC        Denial = "nsec"
	DenialNSEC3       Denial = "nsec3"
	DenialNSEC3OptOut Denial = "nsec3-optout"
	DenialNone        Denial = "none"
)

// Options control synthetic zone generation.
type Options struct {
	Origin      string
	Serial      uint32
	Delegations int
	SecurePct   int // 0-100 of delegations that get DS
	Denial      Denial
	Algorithm   uint8
	NSEC3Iters  uint16
	NSEC3Salt   string
	TTL         uint32
	Inception   uint32
	Expiration  uint32
	Seed        int64
	AddWildcard bool
	AddDNAME    bool
	ZONEMD      bool
	DualAlg     bool
	ExtraUnused bool
}

func (o *Options) defaults() {
	if o.Origin == "" {
		o.Origin = "example.com."
	}
	o.Origin = dnsname.Canonical(o.Origin)
	if o.Serial == 0 {
		o.Serial = 1
	}
	if o.TTL == 0 {
		o.TTL = 3600
	}
	if o.Algorithm == 0 {
		o.Algorithm = dns.ECDSAP256SHA256
	}
	if o.Denial == "" {
		o.Denial = DenialNSEC3OptOut
	}
	if o.SecurePct == 0 && o.Delegations > 0 {
		o.SecurePct = 5
	}
	if o.Expiration == 0 {
		o.Expiration = 0x7fffffff
	}
	if o.Inception == 0 {
		o.Inception = 1
	}
}

type Generated struct {
	Store   *zone.Store
	KSK     *dns.DNSKEY
	ZSK     *dns.DNSKEY
	KSKPriv crypto.Signer
	ZSKPriv crypto.Signer
	Counts  Counts
}

type Counts struct {
	Records int
	RRSIGs  int
	NSEC3   int
	DNSKEYs int
	Deleg   int
	Secure  int
}

// Small builds a modest signed zone suitable for unit tests.
func Small(origin string) (*Generated, error) {
	return Generate(Options{Origin: origin, Delegations: 8, SecurePct: 50, Denial: DenialNSEC3OptOut, Seed: 1})
}

// Large builds a TLD-shaped zone with n approximate records.
// Each delegation contributes ~NS(4)+glue(4)+optional DS + NSEC3 + RRSIGs.
func Large(n int, seed int64) (*Generated, error) {
	deleg := n / 12
	if deleg < 1 {
		deleg = 1
	}
	return Generate(Options{
		Origin:      "large.test.",
		Delegations: deleg,
		SecurePct:   5,
		Denial:      DenialNSEC3OptOut,
		Seed:        seed,
	})
}

func Generate(opt Options) (*Generated, error) {
	opt.defaults()
	rng := rand.New(rand.NewSource(opt.Seed))

	ksk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: opt.TTL}, Flags: 257, Protocol: 3, Algorithm: opt.Algorithm}
	zsk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: opt.TTL}, Flags: 256, Protocol: 3, Algorithm: opt.Algorithm}
	bits := keyBits(opt.Algorithm)
	kpriv, err := ksk.Generate(bits)
	if err != nil {
		return nil, fmt.Errorf("ksk: %w", err)
	}
	zpriv, err := zsk.Generate(bits)
	if err != nil {
		return nil, fmt.Errorf("zsk: %w", err)
	}
	kskSigner, ok1 := kpriv.(crypto.Signer)
	zskSigner, ok2 := zpriv.(crypto.Signer)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("keys are not signers")
	}

	var rrs []dns.RR
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: opt.TTL},
		Ns:      "ns1." + opt.Origin,
		Mbox:    "hostmaster." + opt.Origin,
		Serial:  opt.Serial,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	rrs = append(rrs, soa)
	rrs = append(rrs, &dns.NS{Hdr: dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: opt.TTL}, Ns: "ns1." + opt.Origin})
	rrs = append(rrs, &dns.NS{Hdr: dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: opt.TTL}, Ns: "ns2." + opt.Origin})
	rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{Name: "ns1." + opt.Origin, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: opt.TTL}, A: []byte{192, 0, 2, 1}})
	rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{Name: "ns2." + opt.Origin, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: opt.TTL}, A: []byte{192, 0, 2, 2}})
	if opt.Denial != DenialNone {
		rrs = append(rrs, ksk, zsk)
	}
	if opt.ExtraUnused {
		unused := &dns.DNSKEY{Hdr: dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: opt.TTL}, Flags: 256, Protocol: 3, Algorithm: opt.Algorithm}
		if _, err := unused.Generate(keyBits(opt.Algorithm)); err != nil {
			return nil, err
		}
		rrs = append(rrs, unused)
	}

	secure := 0
	for i := 0; i < opt.Delegations; i++ {
		label := fmt.Sprintf("d%05d", i)
		owner := label + "." + opt.Origin
		for n := 1; n <= 4; n++ {
			ns := fmt.Sprintf("ns%d.%s", n, owner)
			rrs = append(rrs, &dns.NS{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: opt.TTL}, Ns: ns})
			ip := []byte{192, 0, 2, byte(1 + (i+n)%250)}
			rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{Name: ns, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: opt.TTL}, A: ip})
		}
		if rng.Intn(100) < opt.SecurePct {
			secure++
			child := &dns.DNSKEY{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: opt.TTL}, Flags: 257, Protocol: 3, Algorithm: opt.Algorithm}
			if _, err := child.Generate(keyBits(opt.Algorithm)); err != nil {
				return nil, err
			}
			ds := child.ToDS(dns.SHA256)
			ds.Hdr.Name = owner
			ds.Hdr.Ttl = opt.TTL
			ds.Hdr.Class = dns.ClassINET
			ds.Hdr.Rrtype = dns.TypeDS
			rrs = append(rrs, ds)
		}
	}
	if opt.AddWildcard {
		rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{Name: "*." + opt.Origin, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: opt.TTL}, A: []byte{192, 0, 2, 99}})
	}
	if opt.AddDNAME {
		rrs = append(rrs, &dns.DNAME{Hdr: dns.RR_Header{Name: "alias." + opt.Origin, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: opt.TTL}, Target: "target." + opt.Origin})
		rrs = append(rrs, &dns.TXT{Hdr: dns.RR_Header{Name: "ent.child." + opt.Origin, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: opt.TTL}, Txt: []string{"empty-nonterminal-parent"}})
	}
	if opt.ZONEMD && opt.Denial != DenialNone {
		// Placeholder digest so NSEC/NSEC3 bitmaps include ZONEMD before signing.
		rrs = append(rrs, &dns.ZONEMD{
			Hdr:    dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeZONEMD, Class: dns.ClassINET, Ttl: opt.TTL},
			Serial: opt.Serial,
			Scheme: 1,
			Hash:   1,
			Digest: strings.Repeat("00", 48),
		})
	}

	if opt.Denial == DenialNSEC3 || opt.Denial == DenialNSEC3OptOut {
		flags := uint8(0)
		if opt.Denial == DenialNSEC3OptOut {
			flags = 1
		}
		salt := saltOrDash(opt.NSEC3Salt)
		saltLen := uint8(0)
		if salt != "-" && salt != "" {
			saltLen = uint8(len(salt) / 2)
		}
		rrs = append(rrs, &dns.NSEC3PARAM{
			Hdr:        dns.RR_Header{Name: opt.Origin, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0},
			Hash:       dns.SHA1,
			Flags:      0,
			Iterations: opt.NSEC3Iters,
			SaltLength: saltLen,
			Salt:       salt,
		})
		nsec3s, err := buildNSEC3(opt, rrs, flags)
		if err != nil {
			return nil, err
		}
		rrs = append(rrs, nsec3s...)
	} else if opt.Denial == DenialNSEC {
		nsecs := buildNSEC(opt, rrs)
		rrs = append(rrs, nsecs...)
	}

	if opt.Denial != DenialNone {
		signed, err := signZone(opt, rrs, ksk, zsk, kskSigner, zskSigner)
		if err != nil {
			return nil, err
		}
		rrs = signed
	}

	st, err := zone.FromAXFR(opt.Origin, rrs)
	if err != nil {
		return nil, err
	}
	g := &Generated{
		Store:   st,
		KSK:     ksk,
		ZSK:     zsk,
		KSKPriv: kskSigner,
		ZSKPriv: zskSigner,
		Counts: Counts{
			Records: st.RecordCount(),
			RRSIGs:  st.RRSIGCount(),
			NSEC3:   st.NSEC3Count(),
			DNSKEYs: 2,
			Deleg:   opt.Delegations,
			Secure:  secure,
		},
	}
	if opt.ZONEMD && opt.Denial != DenialNone {
		if err := finalizeZONEMD(g, opt); err != nil {
			return nil, err
		}
		g.Counts.Records = st.RecordCount()
		g.Counts.RRSIGs = st.RRSIGCount()
	}
	return g, nil
}

// finalizeZONEMD replaces the placeholder apex ZONEMD digest with a matching
// SIMPLE SHA-384 digest and re-signs the ZONEMD RRset.
func finalizeZONEMD(g *Generated, opt Options) error {
	apex := g.Store.Apex()
	if apex == nil {
		return fmt.Errorf("no apex for ZONEMD")
	}
	rrs, err := apex.UnpackType(dns.TypeZONEMD)
	if err != nil || len(rrs) == 0 {
		return fmt.Errorf("placeholder ZONEMD missing: %w", err)
	}
	old := rrs[0].(*dns.ZONEMD)
	digest, err := dnssec.ComputeZONEMD(g.Store, old.Scheme, old.Hash)
	if err != nil {
		return err
	}
	neu := &dns.ZONEMD{
		Hdr:    dns.RR_Header{Name: old.Hdr.Name, Rrtype: dns.TypeZONEMD, Class: dns.ClassINET, Ttl: old.Hdr.Ttl},
		Serial: old.Serial,
		Scheme: old.Scheme,
		Hash:   old.Hash,
		Digest: hex.EncodeToString(digest),
	}
	// Drop old ZONEMD and any covering RRSIG, then add + sign the correct digest.
	sigs, err := apex.UnpackType(dns.TypeRRSIG)
	if err != nil {
		return err
	}
	for _, rr := range sigs {
		if sig := rr.(*dns.RRSIG); sig.TypeCovered == dns.TypeZONEMD {
			if err := g.Store.RemoveRR(sig); err != nil {
				return err
			}
		}
	}
	if err := g.Store.RemoveRR(old); err != nil {
		return err
	}
	if err := g.Store.AddRR(neu); err != nil {
		return err
	}
	sig, err := ResignRRSet([]dns.RR{neu}, g.ZSK, g.ZSKPriv, opt.Inception, opt.Expiration)
	if err != nil {
		return err
	}
	return g.Store.AddRR(sig)
}

func keyBits(alg uint8) int {
	switch alg {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		return 2048
	case dns.ECDSAP384SHA384:
		return 384
	default:
		return 256
	}
}

func saltOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func namesFrom(rrs []dns.RR) map[string]map[uint16]struct{} {
	m := map[string]map[uint16]struct{}{}
	for _, rr := range rrs {
		n := dnsname.Canonical(rr.Header().Name)
		if m[n] == nil {
			m[n] = map[uint16]struct{}{}
		}
		m[n][rr.Header().Rrtype] = struct{}{}
	}
	return m
}

func isDelegation(types map[uint16]struct{}, origin, name string) bool {
	if name == origin {
		return false
	}
	_, ns := types[dns.TypeNS]
	return ns
}

func underDelegation(byName map[string]map[uint16]struct{}, origin, name string) bool {
	p := dnsname.Parent(name)
	for p != origin && p != "." && p != "" {
		if types, ok := byName[p]; ok {
			if _, ns := types[dns.TypeNS]; ns {
				return true
			}
		}
		next := dnsname.Parent(p)
		if next == p {
			break
		}
		p = next
	}
	return false
}

func buildNSEC(opt Options, rrs []dns.RR) []dns.RR {
	byName := namesFrom(rrs)
	var names []string
	for n := range byName {
		names = append(names, n)
	}
	// include empty non-terminals
	names = addENTs(names, opt.Origin)
	sortCanon(names)
	var out []dns.RR
	for i, name := range names {
		next := names[(i+1)%len(names)]
		types := byName[name]
		if types == nil {
			types = map[uint16]struct{}{}
		}
		types[dns.TypeNSEC] = struct{}{}
		types[dns.TypeRRSIG] = struct{}{}
		nsec := &dns.NSEC{
			Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: opt.TTL},
			NextDomain: next,
			TypeBitMap: bitmapOf(types),
		}
		out = append(out, nsec)
	}
	return out
}

func buildNSEC3(opt Options, rrs []dns.RR, flags uint8) ([]dns.RR, error) {
	byName := namesFrom(rrs)
	var names []string
	for n := range byName {
		names = append(names, n)
	}
	names = addENTs(names, opt.Origin)
	type hashed struct {
		hash  string
		name  string
		types map[uint16]struct{}
	}
	var items []hashed
	for _, name := range names {
		types := byName[name]
		if types == nil {
			types = map[uint16]struct{}{}
		}
		if underDelegation(byName, opt.Origin, name) {
			continue // glue is not authoritative
		}
		if isDelegation(types, opt.Origin, name) {
			if _, ds := types[dns.TypeDS]; !ds && flags&1 == 1 {
				continue // opt-out insecure delegation
			}
		}
		h := dns.HashName(name, dns.SHA1, opt.NSEC3Iters, opt.NSEC3Salt)
		items = append(items, hashed{hash: strings.ToLower(h), name: name, types: types})
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].hash < items[i].hash {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	var out []dns.RR
	for i, it := range items {
		next := items[(i+1)%len(items)].hash
		bm := map[uint16]struct{}{}
		for t := range it.types {
			if t == dns.TypeNSEC3 || t == dns.TypeNSEC3PARAM && it.name != opt.Origin {
				continue
			}
			bm[t] = struct{}{}
		}
		bm[dns.TypeRRSIG] = struct{}{}
		owner := strings.ToLower(it.hash) + "." + opt.Origin
		salt := saltOrDash(opt.NSEC3Salt)
		saltLen := uint8(0)
		if salt != "-" && salt != "" {
			saltLen = uint8(len(salt) / 2)
		}
		n3 := &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: opt.TTL},
			Hash:       dns.SHA1,
			Flags:      flags,
			Iterations: opt.NSEC3Iters,
			SaltLength: saltLen,
			Salt:       salt,
			HashLength: 20,
			NextDomain: strings.ToUpper(next),
			TypeBitMap: bitmapOf(bm),
		}
		out = append(out, n3)
	}
	return out, nil
}

func addENTs(names []string, origin string) []string {
	seen := map[string]struct{}{}
	for _, n := range names {
		seen[n] = struct{}{}
	}
	var extra []string
	for _, n := range names {
		if n == origin {
			continue
		}
		p := dnsname.Parent(n)
		for p != origin && p != "." {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				extra = append(extra, p)
			}
			next := dnsname.Parent(p)
			if next == p {
				break
			}
			p = next
		}
	}
	return append(names, extra...)
}

func bitmapOf(types map[uint16]struct{}) []uint16 {
	var out []uint16
	for t := range types {
		out = append(out, t)
	}
	sortU16(out)
	return out
}

func sortCanon(names []string) {
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if zone.CanonicalCmp(names[i], names[j]) > 0 {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
}

func sortU16(a []uint16) {
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}
