package dnsname

import (
	"strings"

	"github.com/miekg/dns"
)

// Canonical returns a lowercase FQDN (always ends with a dot).
func Canonical(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return strings.ToLower(dns.Fqdn(name))
}

// Equal reports whether two names are the same after canonicalisation.
func Equal(a, b string) bool {
	return Canonical(a) == Canonical(b)
}

// IsSubdomain reports whether name is at or under origin.
func IsSubdomain(name, origin string) bool {
	n := Canonical(name)
	o := Canonical(origin)
	if n == o {
		return true
	}
	return strings.HasSuffix(n, "."+o) || (o == "." && n != "")
}

// Parent returns the parent of name, or "." for a TLD / root.
func Parent(name string) string {
	n := Canonical(name)
	if n == "." {
		return "."
	}
	labels := dns.SplitDomainName(n)
	if len(labels) <= 1 {
		return "."
	}
	return Canonical(strings.Join(labels[1:], "."))
}

// Labels returns the number of labels in a canonical name.
func Labels(name string) int {
	return dns.CountLabel(Canonical(name))
}
