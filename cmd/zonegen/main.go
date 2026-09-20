package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/zonegen"
)

func main() {
	origin := flag.String("zone", "example.com.", "origin")
	n := flag.Int("n", 1000, "approximate record target for -large")
	deleg := flag.Int("delegations", 8, "delegations for small zones")
	large := flag.Bool("large", false, "generate a large TLD-shaped zone")
	mutate := flag.String("mutate", "", "optional defect name from the catalogue (flip, RRSIG_EXPIRED, MIXED_NSEC_NSEC3, ...)")
	out := flag.String("out", "", "write zone file (default stdout)")
	examples := flag.String("examples", "", "write the compose defect pack to this zones directory")
	flag.Parse()

	if *examples != "" {
		if err := zonegen.WriteExamplePack(*examples); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote example pack to %s\n", *examples)
		return
	}

	var g *zonegen.Generated
	var err error
	if *large {
		g, err = zonegen.Large(*n, 1)
	} else {
		g, err = zonegen.Generate(zonegen.Options{Origin: *origin, Delegations: *deleg, Seed: 1})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *mutate != "" {
		if err := applyMutate(g, *mutate); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	if err := g.Store.WriteZoneFile(w); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "records=%d rrsigs=%d nsec3=%d\n", g.Counts.Records, g.Counts.RRSIGs, g.Counts.NSEC3)
}

func applyMutate(g *zonegen.Generated, name string) error {
	if name == "flip" {
		return zonegen.FlipRRSIG(g)
	}
	cat := zonegen.Catalogue()
	if m, ok := cat[name]; ok {
		return m(g)
	}
	upper := strings.ToUpper(name)
	if m, ok := cat[upper]; ok {
		return m(g)
	}
	var keys []string
	for k := range cat {
		keys = append(keys, k)
	}
	return fmt.Errorf("unknown mutate %q (want one of %s)", name, strings.Join(keys, ", "))
}
