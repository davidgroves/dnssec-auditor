package config

import (
	"fmt"
	"strconv"
	"time"
)

// Duration is a time.Duration that unmarshals from YAML as a Go duration
// string ("60s", "24h") or as an integer number of seconds.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case string:
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", v, err)
		}
		*d = Duration(parsed)
	case int:
		*d = Duration(time.Duration(v) * time.Second)
	case int64:
		*d = Duration(time.Duration(v) * time.Second)
	case float64:
		*d = Duration(time.Duration(v) * time.Second)
	default:
		return fmt.Errorf("invalid duration type %T", raw)
	}
	return nil
}

func durationOr(raw string) Duration {
	d, err := time.ParseDuration(raw)
	if err != nil {
		panic(err)
	}
	return Duration(d)
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}
