package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"crypto/ed25519"

	"github.com/miekg/dns"
)

// CachedKey is a DNSKEY with a parsed public key.
type CachedKey struct {
	RR     *dns.DNSKEY
	KeyTag uint16
	Flags  uint16
	Alg    uint8
	Pub    crypto.PublicKey
	IsKSK  bool
	IsZone bool
	Used   bool
}

func cacheKeys(keys []*dns.DNSKEY) ([]CachedKey, error) {
	out := make([]CachedKey, 0, len(keys))
	for _, k := range keys {
		ck := CachedKey{
			RR:     k,
			KeyTag: k.KeyTag(),
			Flags:  k.Flags,
			Alg:    k.Algorithm,
			IsKSK:  k.Flags&dns.SEP != 0,
			IsZone: k.Flags&dns.ZONE != 0,
		}
		pub, err := parsePublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("parse DNSKEY %d: %w", ck.KeyTag, err)
		}
		ck.Pub = pub
		out = append(out, ck)
	}
	return out, nil
}

func parsePublicKey(k *dns.DNSKEY) (crypto.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	switch k.Algorithm {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		return parseRSA(raw)
	case dns.ECDSAP256SHA256:
		return parseECDSA(raw, elliptic.P256())
	case dns.ECDSAP384SHA384:
		return parseECDSA(raw, elliptic.P384())
	case dns.ED25519:
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ed25519 key length %d", len(raw))
		}
		return ed25519.PublicKey(raw), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %d", k.Algorithm)
	}
}

func parseRSA(raw []byte) (*rsa.PublicKey, error) {
	if len(raw) < 3 {
		return nil, fmt.Errorf("short RSA key")
	}
	var explen int
	off := 0
	if raw[0] == 0 {
		if len(raw) < 3 {
			return nil, fmt.Errorf("short RSA exponent")
		}
		explen = int(raw[1])<<8 | int(raw[2])
		off = 3
	} else {
		explen = int(raw[0])
		off = 1
	}
	if off+explen >= len(raw) {
		return nil, fmt.Errorf("short RSA modulus")
	}
	e := new(big.Int).SetBytes(raw[off : off+explen])
	n := new(big.Int).SetBytes(raw[off+explen:])
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseECDSA(raw []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	sz := (curve.Params().BitSize + 7) / 8
	if len(raw) != 2*sz {
		return nil, fmt.Errorf("ecdsa key length %d want %d", len(raw), 2*sz)
	}
	x := new(big.Int).SetBytes(raw[:sz])
	y := new(big.Int).SetBytes(raw[sz:])
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func algName(a uint8) string {
	if s, ok := dns.AlgorithmToString[a]; ok {
		return s
	}
	return fmt.Sprintf("ALG%d", a)
}
