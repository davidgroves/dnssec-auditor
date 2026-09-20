package zonegen

import (
	"crypto"
	"fmt"
	"slices"
	"time"

	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

// Mutator applies a named defect to a generated zone's store.
type Mutator func(g *Generated) error

func firstOfType(st *zone.Store, rrtype uint16) (name string, set *zone.RRSet) {
	st.ForEachNode(func(n *zone.Node) bool {
		if n.Name == st.Origin() {
			return true
		}
		if s := n.Set(rrtype); s != nil {
			name = n.Name
			set = s
			return false
		}
		return true
	})
	return name, set
}

func firstDS(st *zone.Store) *zone.Node {
	var found *zone.Node
	st.ForEachNode(func(n *zone.Node) bool {
		if n.HasDS {
			found = n
			return false
		}
		return true
	})
	return found
}

func firstNSEC3(st *zone.Store) *zone.Node {
	var found *zone.Node
	st.ForEachNode(func(n *zone.Node) bool {
		if n.Has(dns.TypeNSEC3) {
			found = n
			return false
		}
		return true
	})
	return found
}

func removeRRs(st *zone.Store, name string, rrtype uint16) error {
	n := st.Lookup(name)
	if n == nil {
		return fmt.Errorf("no node %s", name)
	}
	rrs, err := n.UnpackType(rrtype)
	if err != nil {
		return err
	}
	for _, rr := range rrs {
		if err := st.RemoveRR(rr); err != nil {
			return err
		}
	}
	return nil
}

func replaceRRs(st *zone.Store, old, neu []dns.RR) error {
	for _, rr := range old {
		if err := st.RemoveRR(rr); err != nil {
			return err
		}
	}
	for _, rr := range neu {
		if err := st.AddRR(rr); err != nil {
			return err
		}
	}
	return nil
}

func coveringRRSIG(n *zone.Node, rrtype uint16) (*dns.RRSIG, error) {
	rrs, err := n.UnpackType(dns.TypeRRSIG)
	if err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == rrtype {
			return sig, nil
		}
	}
	return nil, fmt.Errorf("no RRSIG covering %s/%s", n.Name, dns.TypeToString[rrtype])
}

// FlipPair returns the original and corrupted first DS (or apex SOA) RRSIG
// without mutating the store. Apply the pair via testprimary.Apply.
func FlipPair(g *Generated) (oldRR, newRR *dns.RRSIG, err error) {
	n := firstDS(g.Store)
	rrtype := uint16(dns.TypeDS)
	if n == nil {
		n = g.Store.Apex()
		rrtype = dns.TypeSOA
	}
	sig, err := coveringRRSIG(n, rrtype)
	if err != nil {
		return nil, nil, err
	}
	old := *sig
	neu := *sig
	if len(neu.Signature) > 0 {
		b := []byte(neu.Signature)
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		neu.Signature = string(b)
	}
	return &old, &neu, nil
}

// SignedSerialBump returns a SOA serial increment plus a matching RRSIG,
// without mutating the store.
func SignedSerialBump(g *Generated) (adds, removes []dns.RR, err error) {
	n := g.Store.Apex()
	if n == nil {
		return nil, nil, fmt.Errorf("no apex")
	}
	soas, err := n.UnpackType(dns.TypeSOA)
	if err != nil || len(soas) == 0 {
		return nil, nil, fmt.Errorf("no SOA")
	}
	oldSOA := soas[0].(*dns.SOA)
	oldSig, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return nil, nil, err
	}
	neu := *oldSOA
	neu.Serial++
	newSig, err := ResignRRSet([]dns.RR{&neu}, g.ZSK, g.ZSKPriv, oldSig.Inception, oldSig.Expiration)
	if err != nil {
		return nil, nil, err
	}
	return []dns.RR{&neu, newSig}, []dns.RR{oldSOA, oldSig}, nil
}

// FlipRRSIG corrupts the first DS (or apex SOA) signature byte.
func FlipRRSIG(g *Generated) error {
	n := firstDS(g.Store)
	rrtype := uint16(dns.TypeDS)
	if n == nil {
		n = g.Store.Apex()
		rrtype = dns.TypeSOA
	}
	sig, err := coveringRRSIG(n, rrtype)
	if err != nil {
		return err
	}
	old := *sig
	if len(sig.Signature) > 0 {
		b := []byte(sig.Signature)
		// stay valid base64 while changing the payload
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		sig.Signature = string(b)
	}
	return replaceRRs(g.Store, []dns.RR{&old}, []dns.RR{sig})
}

// DropRRSIG removes the RRSIG covering the first DS or apex NS.
func DropRRSIG(g *Generated) error {
	n := firstDS(g.Store)
	rrtype := uint16(dns.TypeDS)
	if n == nil {
		n = g.Store.Apex()
		rrtype = dns.TypeNS
	}
	sig, err := coveringRRSIG(n, rrtype)
	if err != nil {
		return err
	}
	return g.Store.RemoveRR(sig)
}

// ExpireRRSIG re-signs one RRset with a past expiration.
func ExpireRRSIG(g *Generated) error {
	n := g.Store.Apex()
	soa, err := n.UnpackType(dns.TypeSOA)
	if err != nil {
		return err
	}
	old, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return err
	}
	neu, err := ResignRRSet(soa, g.ZSK, g.ZSKPriv, 1, 2)
	if err != nil {
		return err
	}
	return replaceRRs(g.Store, []dns.RR{old}, []dns.RR{neu})
}

// FutureRRSIG re-signs one RRset with a future inception.
func FutureRRSIG(g *Generated) error {
	n := g.Store.Apex()
	soa, err := n.UnpackType(dns.TypeSOA)
	if err != nil {
		return err
	}
	old, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return err
	}
	neu, err := ResignRRSet(soa, g.ZSK, g.ZSKPriv, 0x7ffff000, 0x7fffffff)
	if err != nil {
		return err
	}
	return replaceRRs(g.Store, []dns.RR{old}, []dns.RR{neu})
}

// UnknownKeyRRSIG signs SOA with a key not in the DNSKEY set.
func UnknownKeyRRSIG(g *Generated) error {
	n := g.Store.Apex()
	soa, err := n.UnpackType(dns.TypeSOA)
	if err != nil {
		return err
	}
	old, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return err
	}
	foreign := &dns.DNSKEY{Hdr: dns.RR_Header{Name: g.Store.Origin(), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 256, Protocol: 3, Algorithm: g.ZSK.Algorithm}
	priv, err := foreign.Generate(keyBits(g.ZSK.Algorithm))
	if err != nil {
		return err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("foreign key is not a signer")
	}
	neu, err := ResignRRSet(soa, foreign, signer, 1, 0x7fffffff)
	if err != nil {
		return err
	}
	return replaceRRs(g.Store, []dns.RR{old}, []dns.RR{neu})
}

// LabelsMismatch sets RRSIG.Labels to an impossible value.
func LabelsMismatch(g *Generated) error {
	n := g.Store.Apex()
	sig, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return err
	}
	old := *sig
	sig.Labels = 99
	return replaceRRs(g.Store, []dns.RR{&old}, []dns.RR{sig})
}

// TTLMismatch sets OrigTTL on the SOA RRSIG so it no longer matches the RRset TTL.
func TTLMismatch(g *Generated) error {
	n := g.Store.Apex()
	sig, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return err
	}
	old := *sig
	sig.OrigTtl = 1
	return replaceRRs(g.Store, []dns.RR{&old}, []dns.RR{sig})
}

// ExpiringSoon re-signs SOA so it expires shortly after the unit-test clock (unix 1000).
func ExpiringSoon(g *Generated) error {
	n := g.Store.Apex()
	soa, err := n.UnpackType(dns.TypeSOA)
	if err != nil {
		return err
	}
	old, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return err
	}
	neu, err := ResignRRSet(soa, g.ZSK, g.ZSKPriv, 1, 1060)
	if err != nil {
		return err
	}
	return replaceRRs(g.Store, []dns.RR{old}, []dns.RR{neu})
}

// FakeZONEMD inserts a SIMPLE SHA-384 ZONEMD with a zero digest.
func FakeZONEMD(g *Generated) error {
	zmd := &dns.ZONEMD{
		Hdr:    dns.RR_Header{Name: g.Store.Origin(), Rrtype: dns.TypeZONEMD, Class: dns.ClassINET, Ttl: 3600},
		Serial: g.Store.Serial(),
		Scheme: 1,
		Hash:   1,
		Digest: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}
	return g.Store.AddRR(zmd)
}

// DNSKEYSignedByZSKOnly removes KSK signatures from the DNSKEY RRset.
func DNSKEYSignedByZSKOnly(g *Generated) error {
	n := g.Store.Apex()
	rrs, err := n.UnpackType(dns.TypeRRSIG)
	if err != nil {
		return err
	}
	for _, rr := range rrs {
		sig := rr.(*dns.RRSIG)
		if sig.TypeCovered == dns.TypeDNSKEY && sig.KeyTag == g.KSK.KeyTag() {
			if err := g.Store.RemoveRR(sig); err != nil {
				return err
			}
		}
	}
	return nil
}

func DropNSEC3(g *Generated) error {
	n := firstNSEC3(g.Store)
	if n == nil {
		return fmt.Errorf("no NSEC3")
	}
	return removeRRs(g.Store, n.Name, dns.TypeNSEC3)
}

func BreakNSEC3Chain(g *Generated) error {
	n := firstNSEC3(g.Store)
	if n == nil {
		return fmt.Errorf("no NSEC3")
	}
	rrs, err := n.UnpackType(dns.TypeNSEC3)
	if err != nil || len(rrs) == 0 {
		return fmt.Errorf("no NSEC3 rr")
	}
	n3 := rrs[0].(*dns.NSEC3)
	old := *n3
	n3.NextDomain = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	return replaceRRs(g.Store, []dns.RR{&old}, []dns.RR{n3})
}

func NSEC3BitmapDropDS(g *Generated) error {
	ds := firstDS(g.Store)
	if ds == nil {
		return fmt.Errorf("no DS")
	}
	// find NSEC3 whose bitmap includes DS — the hashed owner of the DS name
	var target *zone.Node
	g.Store.ForEachNode(func(n *zone.Node) bool {
		if !n.Has(dns.TypeNSEC3) {
			return true
		}
		rrs, err := n.UnpackType(dns.TypeNSEC3)
		if err != nil || len(rrs) == 0 {
			return true
		}
		n3 := rrs[0].(*dns.NSEC3)
		for _, t := range n3.TypeBitMap {
			if t == dns.TypeDS {
				target = n
				return false
			}
		}
		return true
	})
	if target == nil {
		return fmt.Errorf("no NSEC3 with DS bit")
	}
	rrs, _ := target.UnpackType(dns.TypeNSEC3)
	n3 := rrs[0].(*dns.NSEC3)
	old := *n3
	var bm []uint16
	for _, t := range n3.TypeBitMap {
		if t != dns.TypeDS {
			bm = append(bm, t)
		}
	}
	n3.TypeBitMap = bm
	return replaceRRs(g.Store, []dns.RR{&old}, []dns.RR{n3})
}

func BreakNSECChain(g *Generated) error {
	var n *zone.Node
	g.Store.ForEachNode(func(nn *zone.Node) bool {
		if nn.Has(dns.TypeNSEC) {
			n = nn
			return false
		}
		return true
	})
	if n == nil {
		return fmt.Errorf("no NSEC")
	}
	rrs, err := n.UnpackType(dns.TypeNSEC)
	if err != nil || len(rrs) == 0 {
		return err
	}
	nsec := rrs[0].(*dns.NSEC)
	old := *nsec
	nsec.NextDomain = "zzz-broken." + g.Store.Origin()
	return replaceRRs(g.Store, []dns.RR{&old}, []dns.RR{nsec})
}

func DropNSEC(g *Generated) error {
	var n *zone.Node
	g.Store.ForEachNode(func(nn *zone.Node) bool {
		if nn.Has(dns.TypeNSEC) && nn.IsDelegation {
			n = nn
			return false
		}
		return true
	})
	if n == nil {
		g.Store.ForEachNode(func(nn *zone.Node) bool {
			if nn.Has(dns.TypeNSEC) && nn.Name != g.Store.Origin() {
				n = nn
				return false
			}
			return true
		})
	}
	if n == nil {
		return fmt.Errorf("no NSEC")
	}
	return removeRRs(g.Store, n.Name, dns.TypeNSEC)
}

func NSEC3PARAMMismatch(g *Generated) error {
	apex := g.Store.Apex()
	rrs, err := apex.UnpackType(dns.TypeNSEC3PARAM)
	if err != nil || len(rrs) == 0 {
		return fmt.Errorf("no NSEC3PARAM")
	}
	p := rrs[0].(*dns.NSEC3PARAM)
	old := *p
	p.Iterations = 10
	return replaceRRs(g.Store, []dns.RR{&old}, []dns.RR{p})
}

// MixDenial adds an NSEC3PARAM to an NSEC-signed zone so both denial
// mechanisms are present.
func MixDenial(g *Generated) error {
	p := &dns.NSEC3PARAM{
		Hdr:        dns.RR_Header{Name: g.Store.Origin(), Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 0},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 0,
		Salt:       "-",
	}
	return g.Store.AddRR(p)
}

// MixNSEC adds a plaintext NSEC at the apex of an NSEC3-signed zone.
func MixNSEC(g *Generated) error {
	bitmap := []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeNSEC3PARAM}
	slices.Sort(bitmap)
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: g.Store.Origin(), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "zzz." + g.Store.Origin(),
		TypeBitMap: bitmap,
	}
	return g.Store.AddRR(nsec)
}

// ExpiringSoonLive re-signs SOA so it expires about 36 hours from now.
func ExpiringSoonLive(g *Generated) error {
	n := g.Store.Apex()
	soa, err := n.UnpackType(dns.TypeSOA)
	if err != nil {
		return err
	}
	old, err := coveringRRSIG(n, dns.TypeSOA)
	if err != nil {
		return err
	}
	now := uint32(time.Now().Unix())
	neu, err := ResignRRSet(soa, g.ZSK, g.ZSKPriv, now-3600, now+36*3600)
	if err != nil {
		return err
	}
	return replaceRRs(g.Store, []dns.RR{old}, []dns.RR{neu})
}

// Catalogue maps finding codes / names to mutators.
func Catalogue() map[string]Mutator {
	return map[string]Mutator{
		"RRSIG_INVALID":            FlipRRSIG,
		"RRSIG_MISSING":            DropRRSIG,
		"RRSIG_EXPIRED":            ExpireRRSIG,
		"RRSIG_NOT_YET_VALID":      FutureRRSIG,
		"RRSIG_UNKNOWN_KEY":        UnknownKeyRRSIG,
		"RRSIG_LABELS_MISMATCH":    LabelsMismatch,
		"DNSKEY_NOT_SIGNED_BY_KSK": DNSKEYSignedByZSKOnly,
		"NSEC3_MISSING":            DropNSEC3,
		"NSEC3_CHAIN_BROKEN":       BreakNSEC3Chain,
		"NSEC3_BITMAP_MISMATCH":    NSEC3BitmapDropDS,
		"NSEC3PARAM_MISMATCH":      NSEC3PARAMMismatch,
		"NSEC_MISSING":             DropNSEC,
		"NSEC_CHAIN_BROKEN":        BreakNSECChain,
		"RRSIG_TTL_MISMATCH":       TTLMismatch,
		"RRSIG_EXPIRING_SOON":      ExpiringSoon,
		"ZONEMD_MISMATCH":          FakeZONEMD,
		"MIXED_NSEC_NSEC3":         MixDenial,
		"MIXED_NSEC3_PLUS_NSEC":    MixNSEC,
		"RRSIG_EXPIRING_SOON_LIVE": ExpiringSoonLive,
	}
}
