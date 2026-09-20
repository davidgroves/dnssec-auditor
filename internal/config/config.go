package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/davidgroves/dnssec-auditor/internal/dnsname"
	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML configuration.
type Config struct {
	TSIGKeys     []TSIGKey          `yaml:"tsig_keys"`
	Servers      []Server           `yaml:"servers"`
	Zones        []Zone             `yaml:"zones"`
	Catalogs     []Catalog          `yaml:"catalogs"`
	Refresh      RefreshConfig      `yaml:"refresh"`
	Notify       NotifyConfig       `yaml:"notify"`
	Verification VerificationConfig `yaml:"verification"`
	ChainOfTrust ChainConfig        `yaml:"chain_of_trust"`
	Webhooks     WebhookConfig      `yaml:"webhooks"`
	State        StateConfig        `yaml:"state"`
	API          APIConfig          `yaml:"api"`
	Logging      LoggingConfig      `yaml:"logging"`
	Theme        ThemeConfig        `yaml:"theme"`
}

type TSIGKey struct {
	Name      string `yaml:"name"`
	Secret    string `yaml:"secret"`
	Algorithm string `yaml:"algorithm"`
}

type Server struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	TSIGKey string `yaml:"tsig_key"`
}

type Zone struct {
	Name    string   `yaml:"name"`
	Servers []string `yaml:"servers"`
	TSIGKey string   `yaml:"tsig_key"`
}

type Catalog struct {
	Name          string   `yaml:"name"`
	Servers       []string `yaml:"servers"`
	TSIGKey       string   `yaml:"tsig_key"`
	MemberServers []string `yaml:"member_servers"`
	MemberTSIGKey string   `yaml:"member_tsig_key"`
	Verify        bool     `yaml:"verify"`
}

type RefreshConfig struct {
	MinInterval         Duration `yaml:"min_interval"`
	MaxInterval         Duration `yaml:"max_interval"`
	RetryMin            Duration `yaml:"retry_min"`
	RetryMax            Duration `yaml:"retry_max"`
	Jitter              float64  `yaml:"jitter"`
	PreferIXFR          bool     `yaml:"prefer_ixfr"`
	ConcurrentTransfers int      `yaml:"concurrent_transfers"`
	ProbeAllServers     bool     `yaml:"probe_all_servers"`
	SerialSkewWarning   int      `yaml:"serial_skew_warning"`
	SerialSkewGrace     Duration `yaml:"serial_skew_grace"`
	AXFRTimeout         Duration `yaml:"axfr_timeout"`
	SOATimeout          Duration `yaml:"soa_timeout"`
}

type NotifyConfig struct {
	Enabled        bool     `yaml:"enabled"`
	BindAddress    string   `yaml:"bind_address"`
	UDPPort        int      `yaml:"udp_port"`
	TCPPort        int      `yaml:"tcp_port"`
	RequireTSIG    bool     `yaml:"require_tsig"`
	TSIGKey        string   `yaml:"tsig_key"`
	AllowedSources []string `yaml:"allowed_sources"`
}

type VerificationConfig struct {
	Workers                 int      `yaml:"workers"`
	ClockSkew               Duration `yaml:"clock_skew"`
	ExpiryWarning           Duration `yaml:"expiry_warning"`
	ExpiryCheckInterval     Duration `yaml:"expiry_check_interval"`
	FullReverifyInterval    Duration `yaml:"full_reverify_interval"`
	FullReverifyWhenInvalid bool     `yaml:"full_reverify_when_invalid"`
	ZONEMD                  string   `yaml:"zonemd"` // auto | on | off
	// ZONEMDMaxAge, when >0, forces a full verify (including ZONEMD digest)
	// if the last ZONEMD check is older than this. Zero means only full
	// verifies (AXFR / escalate) recheck ZONEMD; incremental IXFR skips it.
	ZONEMDMaxAge Duration      `yaml:"zonemd_max_age"`
	Hygiene      HygieneConfig `yaml:"hygiene"`
}

type HygieneConfig struct {
	Enabled              bool     `yaml:"enabled"`
	NSEC3MaxIterations   int      `yaml:"nsec3_max_iterations"`
	WarnNSEC3Salt        bool     `yaml:"warn_nsec3_salt"`
	DeprecatedAlgorithms []string `yaml:"deprecated_algorithms"`
	WarnRRSIGTTLMismatch bool     `yaml:"warn_rrsig_ttl_mismatch"`
}

type ChainConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Mode         string   `yaml:"mode"` // resolver | authoritative
	Resolvers    []string `yaml:"resolvers"`
	Interval     Duration `yaml:"interval"`
	RequireMatch bool     `yaml:"require_match"`
}

type WebhookConfig struct {
	Enabled      bool            `yaml:"enabled"`
	Timeout      Duration        `yaml:"timeout"`
	MaxRetries   int             `yaml:"max_retries"`
	RetryBackoff Duration        `yaml:"retry_backoff"`
	QueueSize    int             `yaml:"queue_size"`
	Targets      []WebhookTarget `yaml:"targets"`
}

type WebhookTarget struct {
	URL     string            `yaml:"url"`
	Events  []string          `yaml:"events"`
	Zones   []string          `yaml:"zones"`
	Headers map[string]string `yaml:"headers"`
}

type StateConfig struct {
	File          string         `yaml:"file"`
	SaveInterval  Duration       `yaml:"save_interval"`
	ZoneSnapshots SnapshotConfig `yaml:"zone_snapshots"`
}

type SnapshotConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Dir         string   `yaml:"dir"`
	MinInterval Duration `yaml:"min_interval"`
}

type APIConfig struct {
	Listen string `yaml:"listen"`
}

type LoggingConfig struct {
	Format          string  `yaml:"format"` // json | text
	Level           string  `yaml:"level"`
	SampleRate      float64 `yaml:"sample_rate"`
	SlowThresholdMS int     `yaml:"slow_threshold_ms"`
}

type ThemeConfig struct {
	AppName         string            `yaml:"app_name" json:"app_name"`
	DefaultMode     string            `yaml:"default_mode" json:"default_mode"`
	AllowModeToggle bool              `yaml:"allow_mode_toggle" json:"allow_mode_toggle"`
	Logo            string            `yaml:"logo" json:"logo"`
	Dark            map[string]string `yaml:"dark" json:"dark"`
	Light           map[string]string `yaml:"light" json:"light"`
}

// Defaults returns a Config populated with plan defaults.
func Defaults() Config {
	return Config{
		Refresh: RefreshConfig{
			MinInterval:         durationOr("60s"),
			MaxInterval:         durationOr("24h"),
			RetryMin:            durationOr("60s"),
			RetryMax:            durationOr("1h"),
			Jitter:              0.1,
			PreferIXFR:          true,
			ConcurrentTransfers: 4,
			ProbeAllServers:     true,
			SerialSkewWarning:   2,
			SerialSkewGrace:     durationOr("10m"),
			AXFRTimeout:         durationOr("10m"),
			SOATimeout:          durationOr("5s"),
		},
		Notify: NotifyConfig{
			Enabled:     true,
			BindAddress: "0.0.0.0",
			UDPPort:     5354,
			TCPPort:     5354,
		},
		Verification: VerificationConfig{
			ClockSkew:               durationOr("1h"),
			ExpiryWarning:           durationOr("72h"),
			ExpiryCheckInterval:     durationOr("5m"),
			FullReverifyWhenInvalid: true,
			ZONEMD:                  "auto",
			Hygiene: HygieneConfig{
				Enabled:              true,
				NSEC3MaxIterations:   0,
				WarnNSEC3Salt:        true,
				DeprecatedAlgorithms: []string{"RSAMD5", "DSA", "RSASHA1", "DSA-NSEC3-SHA1", "RSASHA1-NSEC3-SHA1", "ECC-GOST"},
				WarnRRSIGTTLMismatch: true,
			},
		},
		ChainOfTrust: ChainConfig{
			Mode:         "resolver",
			Resolvers:    []string{"127.0.0.1:53"},
			Interval:     durationOr("1h"),
			RequireMatch: true,
		},
		Webhooks: WebhookConfig{
			Timeout:      durationOr("10s"),
			MaxRetries:   3,
			RetryBackoff: durationOr("2s"),
			QueueSize:    1000,
		},
		State: StateConfig{
			SaveInterval: durationOr("1m"),
			ZoneSnapshots: SnapshotConfig{
				Dir:         "/var/lib/dnssec-auditor/zones",
				MinInterval: durationOr("1h"),
			},
		},
		API: APIConfig{Listen: ":8080"},
		Logging: LoggingConfig{
			Format:          "json",
			Level:           "info",
			SampleRate:      0.1,
			SlowThresholdMS: 500,
		},
		Theme: ThemeConfig{
			AppName:         "DNSSEC Auditor",
			DefaultMode:     "dark",
			AllowModeToggle: true,
		},
	}
}

// Load reads a YAML config file and applies defaults + validation.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	if path == "" {
		if err := cfg.Normalize(); err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Normalize canonicalises names and fills implied defaults, then validates.
func (c *Config) Normalize() error {
	for i := range c.TSIGKeys {
		if c.TSIGKeys[i].Algorithm == "" {
			c.TSIGKeys[i].Algorithm = "hmac-sha256"
		}
		c.TSIGKeys[i].Name = strings.ToLower(dnsname.Canonical(c.TSIGKeys[i].Name))
	}
	for i := range c.Servers {
		if c.Servers[i].Port == 0 {
			c.Servers[i].Port = 53
		}
	}
	for i := range c.Zones {
		c.Zones[i].Name = dnsname.Canonical(c.Zones[i].Name)
	}
	for i := range c.Catalogs {
		c.Catalogs[i].Name = dnsname.Canonical(c.Catalogs[i].Name)
	}
	if c.Verification.ZONEMD == "" {
		c.Verification.ZONEMD = "auto"
	}
	if c.Refresh.ConcurrentTransfers <= 0 {
		c.Refresh.ConcurrentTransfers = 4
	}
	if c.Refresh.Jitter < 0 || c.Refresh.Jitter > 1 {
		return fmt.Errorf("refresh.jitter must be between 0 and 1")
	}
	switch strings.ToLower(c.Verification.ZONEMD) {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("verification.zonemd must be auto, on, or off")
	}
	switch strings.ToLower(c.ChainOfTrust.Mode) {
	case "resolver", "authoritative", "":
	default:
		return fmt.Errorf("chain_of_trust.mode must be resolver or authoritative")
	}
	return c.validate()
}

func (c *Config) validate() error {
	keys := map[string]TSIGKey{}
	for _, k := range c.TSIGKeys {
		if k.Name == "" || k.Secret == "" {
			return fmt.Errorf("tsig_keys entries need name and secret")
		}
		keys[k.Name] = k
	}
	servers := map[string]Server{}
	for _, s := range c.Servers {
		if s.Name == "" || s.Address == "" {
			return fmt.Errorf("servers entries need name and address")
		}
		if s.TSIGKey != "" && !hasTSIG(keys, s.TSIGKey) {
			return fmt.Errorf("server %q references unknown tsig_key %q", s.Name, s.TSIGKey)
		}
		servers[s.Name] = s
	}
	for _, z := range c.Zones {
		if z.Name == "" {
			return fmt.Errorf("zones entries need a name")
		}
		if len(z.Servers) == 0 {
			return fmt.Errorf("zone %q has no servers", z.Name)
		}
		for _, name := range z.Servers {
			if _, ok := servers[name]; !ok {
				return fmt.Errorf("zone %q references unknown server %q", z.Name, name)
			}
		}
		if z.TSIGKey != "" && !hasTSIG(keys, z.TSIGKey) {
			return fmt.Errorf("zone %q references unknown tsig_key %q", z.Name, z.TSIGKey)
		}
	}
	for _, cat := range c.Catalogs {
		if cat.Name == "" {
			return fmt.Errorf("catalogs entries need a name")
		}
		for _, name := range cat.Servers {
			if _, ok := servers[name]; !ok {
				return fmt.Errorf("catalog %q references unknown server %q", cat.Name, name)
			}
		}
		for _, name := range cat.MemberServers {
			if _, ok := servers[name]; !ok {
				return fmt.Errorf("catalog %q references unknown member_server %q", cat.Name, name)
			}
		}
	}
	if c.Notify.TSIGKey != "" && !hasTSIG(keys, c.Notify.TSIGKey) {
		return fmt.Errorf("notify.tsig_key references unknown key %q", c.Notify.TSIGKey)
	}
	return nil
}

func hasTSIG(keys map[string]TSIGKey, name string) bool {
	if _, ok := keys[name]; ok {
		return true
	}
	_, ok := keys[dnsname.Canonical(name)]
	return ok
}

// ServerByName looks up a named server.
func (c *Config) ServerByName(name string) (Server, bool) {
	for _, s := range c.Servers {
		if s.Name == name {
			return s, true
		}
	}
	return Server{}, false
}

// TSIGByName looks up a named TSIG key. The name may or may not be a FQDN.
func (c *Config) TSIGByName(name string) (TSIGKey, bool) {
	canon := dnsname.Canonical(name)
	for _, k := range c.TSIGKeys {
		if k.Name == name || k.Name == canon || dnsname.Canonical(k.Name) == canon {
			return k, true
		}
	}
	return TSIGKey{}, false
}

// ResolveServers returns the Server records referenced by names.
func (c *Config) ResolveServers(names []string) []Server {
	out := make([]Server, 0, len(names))
	for _, n := range names {
		if s, ok := c.ServerByName(n); ok {
			out = append(out, s)
		}
	}
	return out
}
