package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration wraps time.Duration so YAML can express it as "30s" or "1h30m"
// instead of a nanosecond count.
type Duration time.Duration

// UnmarshalYAML accepts a Go duration string, or a bare number of seconds.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}

	switch v := raw.(type) {
	case string:
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("invalid duration %q: use a form like 30s, 5m or 1h30m", v)
		}
		*d = Duration(parsed)
	case int:
		*d = Duration(time.Duration(v) * time.Second)
	case float64:
		*d = Duration(time.Duration(v * float64(time.Second)))
	default:
		return fmt.Errorf("invalid duration %v: expected a string like \"30s\"", raw)
	}
	return nil
}

// MarshalYAML renders the duration back as a readable string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Duration returns the wrapped standard-library value.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// ByteSize wraps a byte count so YAML can express it as "35MB" rather than
// 36700160. Both decimal (MB) and binary (MiB) suffixes are accepted, because
// operators reach for whichever they saw in the Exchange documentation.
type ByteSize int64

var byteUnits = []struct {
	suffix string
	factor int64
}{
	{"KIB", 1 << 10},
	{"MIB", 1 << 20},
	{"GIB", 1 << 30},
	{"KB", 1000},
	{"MB", 1000 * 1000},
	{"GB", 1000 * 1000 * 1000},
	{"K", 1 << 10},
	{"M", 1 << 20},
	{"G", 1 << 30},
	{"B", 1},
}

// UnmarshalYAML accepts "35MB", "35MiB", "35000000" or a YAML integer.
func (b *ByteSize) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}

	switch v := raw.(type) {
	case int:
		if v < 0 {
			return fmt.Errorf("invalid size %d: must not be negative", v)
		}
		*b = ByteSize(v)
	case string:
		parsed, err := parseByteSize(v)
		if err != nil {
			return err
		}
		*b = parsed
	default:
		return fmt.Errorf("invalid size %v: expected a number or a string like \"35MB\"", raw)
	}
	return nil
}

// MarshalYAML renders the size back as a readable string.
func (b ByteSize) MarshalYAML() (any, error) { return b.String(), nil }

// Bytes returns the raw byte count.
func (b ByteSize) Bytes() int64 { return int64(b) }

func (b ByteSize) String() string {
	n := int64(b)
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return strconv.FormatInt(n/(1<<30), 10) + "GiB"
	case n >= 1<<20 && n%(1<<20) == 0:
		return strconv.FormatInt(n/(1<<20), 10) + "MiB"
	case n >= 1<<10 && n%(1<<10) == 0:
		return strconv.FormatInt(n/(1<<10), 10) + "KiB"
	default:
		return strconv.FormatInt(n, 10) + "B"
	}
}

func parseByteSize(s string) (ByteSize, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("invalid size %q: empty", s)
	}
	upper := strings.ToUpper(trimmed)

	for _, u := range byteUnits {
		digits, ok := strings.CutSuffix(upper, u.suffix)
		if !ok {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(digits), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size %q: %q is not a number", s, digits)
		}
		if n < 0 {
			return 0, fmt.Errorf("invalid size %q: must not be negative", s)
		}
		return ByteSize(n * float64(u.factor)), nil
	}

	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: use a plain number or a suffix such as KB, MB, MiB", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: must not be negative", s)
	}
	return ByteSize(n), nil
}
