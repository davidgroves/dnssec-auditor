package dnssec

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"slices"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/zone"
	"github.com/miekg/dns"
)

func (v *Verifier) verifyZONEMD(st *zone.Store, res *Result) {
	mode := strings.ToLower(v.cfg.ZONEMD)
	apex := st.Apex()
	if apex == nil {
		return
	}
	rrs, err := apex.UnpackType(dns.TypeZONEMD)
	if err != nil {
		return
	}
	if len(rrs) == 0 {
		if mode == "on" {
			res.Findings.Add(NewFinding(ZONEMDMissing, Error, st.Origin(), dns.TypeZONEMD, "ZONEMD required but missing"))
		}
		return
	}
	if mode == "off" {
		return
	}
	res.ZONEMDChecked = true
	ok := false
	for _, rr := range rrs {
		z, is := rr.(*dns.ZONEMD)
		if !is {
			continue
		}
		digest, err := computeZONEMD(st, z.Scheme, z.Hash)
		if err != nil {
			res.Findings.Add(NewFinding(ZONEMDMismatch, Error, st.Origin(), dns.TypeZONEMD, err.Error()))
			continue
		}
		want, err := hex.DecodeString(z.Digest)
		if err != nil {
			res.Findings.Add(NewFinding(ZONEMDMismatch, Error, st.Origin(), dns.TypeZONEMD, "bad ZONEMD digest encoding"))
			continue
		}
		if hex.EncodeToString(digest) == strings.ToLower(z.Digest) || slices.Equal(digest, want) {
			ok = true
		}
	}
	res.ZONEMDOK = ok
	if !ok {
		res.Findings.Add(NewFinding(ZONEMDMismatch, Error, st.Origin(), dns.TypeZONEMD, "ZONEMD digest mismatch"))
	}
}

func computeZONEMD(st *zone.Store, scheme, alg uint8) ([]byte, error) {
	return ComputeZONEMD(st, scheme, alg)
}

// ComputeZONEMD returns the RFC 8976 digest bytes for the given scheme/hash
// over the store. Used by the verifier and by zonegen when emitting a correct ZONEMD.
func ComputeZONEMD(st *zone.Store, scheme, alg uint8) ([]byte, error) {
	var h hash.Hash
	switch alg {
	case 1: // SHA-384
		h = sha512.New384()
	case 2: // SHA-512
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported ZONEMD hash %d", alg)
	}
	rrs, err := st.AllRRs()
	if err != nil {
		return nil, err
	}
	// Canonical sort: name, type, rdata
	slices.SortFunc(rrs, func(a, b dns.RR) int {
		na, nb := strings.ToLower(a.Header().Name), strings.ToLower(b.Header().Name)
		if na != nb {
			return zone.CanonicalCmp(na, nb)
		}
		if a.Header().Rrtype != b.Header().Rrtype {
			return int(a.Header().Rrtype) - int(b.Header().Rrtype)
		}
		return strings.Compare(a.String(), b.String())
	})
	buf := make([]byte, dns.MaxMsgSize)
	for _, rr := range rrs {
		hrr := rr.Header()
		// Omit RRSIG covering ZONEMD
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
			continue
		}
		// Placeholder for ZONEMD at apex (scheme SIMPLE = 1): include owner/type/class/ttl/rdlength but zero digest
		if z, ok := rr.(*dns.ZONEMD); ok && scheme == 1 {
			cp := *z
			cp.Digest = strings.Repeat("00", len(z.Digest)/2)
			rr = &cp
		}
		n, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			return nil, err
		}
		// Canonical form uses lowercase names; PackRR does not always.
		_ = hrr
		if _, err := h.Write(buf[:n]); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}
