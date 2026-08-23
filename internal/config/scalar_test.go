package config

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		want    time.Duration
		wantErr bool
	}{
		{name: "seconds string", yaml: "d: 30s", want: 30 * time.Second},
		{name: "compound", yaml: "d: 1h30m", want: 90 * time.Minute},
		{name: "milliseconds", yaml: "d: 250ms", want: 250 * time.Millisecond},
		{name: "quoted", yaml: `d: "5m"`, want: 5 * time.Minute},
		// A bare number is a common mistake; reading it as seconds is friendlier
		// than reading it as nanoseconds, which is what time.Duration would do.
		{name: "bare integer means seconds", yaml: "d: 45", want: 45 * time.Second},
		{name: "float means seconds", yaml: "d: 1.5", want: 1500 * time.Millisecond},
		{name: "unparseable", yaml: "d: soon", wantErr: true},
		{name: "wrong type", yaml: "d: [1, 2]", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got struct {
				D Duration `yaml:"d"`
			}
			err := yaml.Unmarshal([]byte(tt.yaml), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Unmarshal(%q) = nil error, want error", tt.yaml)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal(%q): %v", tt.yaml, err)
			}
			if got.D.Duration() != tt.want {
				t.Errorf("= %v, want %v", got.D.Duration(), tt.want)
			}
		})
	}
}

func TestDurationRoundTripsThroughYAML(t *testing.T) {
	t.Parallel()

	original := Duration(90 * time.Minute)
	out, err := yaml.Marshal(map[string]Duration{"d": original})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back struct {
		D Duration `yaml:"d"`
	}
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("Unmarshal(%q): %v", out, err)
	}
	if back.D != original {
		t.Errorf("round trip = %v, want %v", back.D, original)
	}
}

func TestByteSizeUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		want    int64
		wantErr bool
	}{
		{name: "plain integer", yaml: "s: 1024", want: 1024},
		{name: "zero", yaml: "s: 0", want: 0},
		{name: "decimal MB", yaml: "s: 35MB", want: 35 * 1000 * 1000},
		{name: "binary MiB", yaml: "s: 35MiB", want: 35 << 20},
		{name: "bare M means MiB", yaml: "s: 4M", want: 4 << 20},
		{name: "lowercase", yaml: "s: 10kb", want: 10 * 1000},
		{name: "with space", yaml: `s: "10 MB"`, want: 10 * 1000 * 1000},
		{name: "GiB", yaml: "s: 2GiB", want: 2 << 30},
		{name: "bytes suffix", yaml: "s: 512B", want: 512},
		{name: "fractional", yaml: "s: 1.5MiB", want: 1572864},
		{name: "string integer", yaml: `s: "2048"`, want: 2048},
		{name: "negative integer", yaml: "s: -1", wantErr: true},
		{name: "negative with suffix", yaml: "s: -1MB", wantErr: true},
		{name: "not a number", yaml: "s: manyMB", wantErr: true},
		{name: "unknown suffix", yaml: "s: 5PB", wantErr: true},
		{name: "empty string", yaml: `s: ""`, wantErr: true},
		{name: "wrong type", yaml: "s: [1]", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got struct {
				S ByteSize `yaml:"s"`
			}
			err := yaml.Unmarshal([]byte(tt.yaml), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Unmarshal(%q) = %d, want error", tt.yaml, got.S.Bytes())
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal(%q): %v", tt.yaml, err)
			}
			if got.S.Bytes() != tt.want {
				t.Errorf("= %d, want %d", got.S.Bytes(), tt.want)
			}
		})
	}
}

func TestByteSizeRoundTripsThroughYAML(t *testing.T) {
	t.Parallel()

	original := ByteSize(35 << 20)
	out, err := yaml.Marshal(map[string]ByteSize{"s": original})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), "35MiB") {
		t.Errorf("Marshal produced %q, want a human-readable size", out)
	}

	var back struct {
		S ByteSize `yaml:"s"`
	}
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("Unmarshal(%q): %v", out, err)
	}
	if back.S != original {
		t.Errorf("round trip = %v, want %v", back.S, original)
	}
}

func TestByteSizeString(t *testing.T) {
	t.Parallel()

	tests := map[int64]string{
		0:         "0B",
		512:       "512B",
		1 << 10:   "1KiB",
		35 << 20:  "35MiB",
		2 << 30:   "2GiB",
		1000000:   "1000000B", // not a clean binary multiple
		1<<20 + 1: "1048577B",
	}
	for in, want := range tests {
		if got := ByteSize(in).String(); got != want {
			t.Errorf("ByteSize(%d).String() = %q, want %q", in, got, want)
		}
	}
}
