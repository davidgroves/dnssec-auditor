package dnsname

import "testing"

func TestCanonical(t *testing.T) {
	if Canonical("Example.COM") != "example.com." {
		t.Fatalf("got %q", Canonical("Example.COM"))
	}
	if Parent("www.example.com.") != "example.com." {
		t.Fatalf("parent %q", Parent("www.example.com."))
	}
	if !IsSubdomain("www.example.com.", "example.com.") {
		t.Fatal("subdomain")
	}
}
