package version

// Version is set at link time via -ldflags "-X github.com/davidgroves/dnssec-auditor/internal/version.Version=..."
var Version = "dev"

// Commit is the git SHA, set at link time.
var Commit = "unknown"

// BuildTime is an RFC3339 timestamp, set at link time.
var BuildTime = "unknown"
