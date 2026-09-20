package zone

import (
	"bytes"
	"fmt"

	"github.com/miekg/dns"
)

// RRSet is a compact in-memory RRset: packed wire RDATA, not dns.RR.
type RRSet struct {
	Type  uint16
	TTL   uint32
	Rdata [][]byte
}

// Clone returns a deep copy.
func (s RRSet) Clone() RRSet {
	out := RRSet{Type: s.Type, TTL: s.TTL, Rdata: make([][]byte, len(s.Rdata))}
	for i, r := range s.Rdata {
		out.Rdata[i] = bytes.Clone(r)
	}
	return out
}

// Unpack expands packed rdata into dns.RR values owned by name.
func (s RRSet) Unpack(name string) ([]dns.RR, error) {
	out := make([]dns.RR, 0, len(s.Rdata))
	for _, rd := range s.Rdata {
		rr, err := unpackOne(name, s.Type, s.TTL, rd)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, nil
}

func unpackOne(name string, rrtype uint16, ttl uint32, wire []byte) (dns.RR, error) {
	rr, _, err := dns.UnpackRR(wire, 0)
	if err != nil {
		return nil, fmt.Errorf("unpack %s/%d: %w", name, rrtype, err)
	}
	h := rr.Header()
	if h.Name == "" {
		h.Name = name
	}
	if h.Ttl == 0 && ttl != 0 {
		h.Ttl = ttl
	}
	_ = rrtype
	return rr, nil
}

// PackRR returns the full uncompressed wire encoding of rr.
func PackRR(rr dns.RR) ([]byte, error) {
	buf := make([]byte, dns.Len(rr)+64)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", rr.Header().Name, err)
	}
	return bytes.Clone(buf[:n]), nil
}

// CompactRRSIG is the parsed form kept on the node for indexes.
type CompactRRSIG struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   []byte
}

func ParseRRSIG(rr *dns.RRSIG) CompactRRSIG {
	return CompactRRSIG{
		TypeCovered: rr.TypeCovered,
		Algorithm:   rr.Algorithm,
		Labels:      rr.Labels,
		OrigTTL:     rr.OrigTtl,
		Expiration:  rr.Expiration,
		Inception:   rr.Inception,
		KeyTag:      rr.KeyTag,
		SignerName:  dns.Fqdn(rr.SignerName),
		Signature:   bytes.Clone(mustBase64(rr.Signature)),
	}
}

func mustBase64(s string) []byte {
	// miekg stores Signature as base64 text. Decode via a throwaway RRSIG
	// pack, or just keep the text and decode when verifying.
	// Easier: keep the original string bytes via dns packing.
	return []byte(s)
}

// RRSIGFromCompact rebuilds a *dns.RRSIG (signature stays as miekg base64 text).
func RRSIGFromCompact(name string, ttl uint32, c CompactRRSIG) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		TypeCovered: c.TypeCovered,
		Algorithm:   c.Algorithm,
		Labels:      c.Labels,
		OrigTtl:     c.OrigTTL,
		Expiration:  c.Expiration,
		Inception:   c.Inception,
		KeyTag:      c.KeyTag,
		SignerName:  c.SignerName,
		Signature:   string(c.Signature),
	}
}
