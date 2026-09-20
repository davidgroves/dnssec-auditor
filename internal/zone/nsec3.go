package zone

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"github.com/miekg/dns"
)

// HashName returns the NSEC3 hash of name using the given parameters.
func HashName(name string, hash uint8, iterations uint16, salt []byte) []byte {
	h := dns.HashName(dnsname.Canonical(name), hash, iterations, hex.EncodeToString(salt))
	b, err := HashFromBase32(h)
	if err != nil {
		return []byte(h)
	}
	return b
}

// HashFromOwner decodes the leftmost label of an NSEC3 owner as a binary hash.
func HashFromOwner(owner string) ([]byte, error) {
	owner = dnsname.Canonical(owner)
	label := owner
	if i := strings.IndexByte(owner, '.'); i >= 0 {
		label = owner[:i]
	}
	return HashFromBase32(label)
}

// HashFromBase32 decodes a base32hex (no pad) NSEC3 hash label.
func HashFromBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimRight(s, "="))
	// miekg uses hex.DecodedLen-style via dns.HashName output which is
	// already unpadded base32hex. Use the decoder from encoding/base32
	// via miekg helper if available; otherwise do it ourselves.
	out, err := decodeBase32Hex(s)
	if err != nil {
		return nil, fmt.Errorf("nsec3 hash %q: %w", s, err)
	}
	return out, nil
}

func decodeBase32Hex(s string) ([]byte, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	if len(s) == 0 {
		return nil, fmt.Errorf("empty")
	}
	// Pad to multiple of 8
	pad := (8 - len(s)%8) % 8
	s = s + strings.Repeat("=", pad)
	out := make([]byte, 0, len(s)*5/8)
	var buf uint64
	var bits uint
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		idx := strings.IndexByte(alphabet, c)
		if idx < 0 {
			if c >= 'a' && c <= 'v' {
				idx = strings.IndexByte(alphabet, c-'a'+'A')
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("invalid base32hex %q", s)
		}
		buf = buf<<5 | uint64(idx)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}

// Base32Hex encodes a binary hash as an unpadded base32hex label.
func Base32Hex(b []byte) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuv"
	if len(b) == 0 {
		return ""
	}
	var out strings.Builder
	var buf uint64
	var bits uint
	for _, by := range b {
		buf = buf<<8 | uint64(by)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(alphabet[(buf>>bits)&31])
		}
	}
	if bits > 0 {
		out.WriteByte(alphabet[(buf<<(5-bits))&31])
	}
	return out.String()
}

// CanonicalCmp compares DNS names in canonical DNSSEC order (label-by-label
// from the right, lowercase).
func CanonicalCmp(a, b string) int {
	al := dns.SplitDomainName(dnsname.Canonical(a))
	bl := dns.SplitDomainName(dnsname.Canonical(b))
	// compare from the right
	for i := 1; i <= len(al) && i <= len(bl); i++ {
		aa := strings.ToLower(al[len(al)-i])
		bb := strings.ToLower(bl[len(bl)-i])
		if aa == bb {
			continue
		}
		if aa < bb {
			return -1
		}
		return 1
	}
	return len(al) - len(bl)
}

// BitmapHas reports whether typ is in the NSEC/NSEC3 type bitmap.
func BitmapHas(types []uint16, typ uint16) bool {
	for _, t := range types {
		if t == typ {
			return true
		}
	}
	return false
}

// ExpectedBitmap returns the types that should appear in an NSEC(3) bitmap
// for node, excluding NSEC3 itself (NSEC3 bitmaps never include NSEC3) and
// including RRSIG / NSEC as appropriate.
func ExpectedBitmap(n *Node, nsec3 bool) []uint16 {
	var out []uint16
	seen := map[uint16]struct{}{}
	add := func(t uint16) {
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, set := range n.Sets {
		if nsec3 && set.Type == dns.TypeNSEC3 {
			continue
		}
		add(set.Type)
	}
	return out
}
