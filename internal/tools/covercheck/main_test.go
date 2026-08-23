package main

import (
	"strings"
	"testing"
)

func TestParseProfileLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		line      string
		wantFile  string
		wantStmts int
		wantCount int
		wantErr   bool
	}{
		{
			name:      "covered block",
			line:      "example.com/m/internal/policy/from.go:12.31,18.2 4 7",
			wantFile:  "example.com/m/internal/policy/from.go",
			wantStmts: 4,
			wantCount: 7,
		},
		{
			name:      "uncovered block",
			line:      "example.com/m/internal/policy/from.go:20.2,21.9 1 0",
			wantFile:  "example.com/m/internal/policy/from.go",
			wantStmts: 1,
			wantCount: 0,
		},
		{
			name:      "path containing a colon is split on the last one",
			line:      "example.com/m/pkg/a:b/f.go:1.1,2.2 3 4",
			wantFile:  "example.com/m/pkg/a:b/f.go",
			wantStmts: 3,
			wantCount: 4,
		},
		{name: "no colon", line: "garbage 1 2", wantErr: true},
		{name: "too few fields", line: "f.go:1.1,2.2 3", wantErr: true},
		{name: "non-numeric statements", line: "f.go:1.1,2.2 x 4", wantErr: true},
		{name: "non-numeric count", line: "f.go:1.1,2.2 3 x", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			file, stmts, count, err := parseProfileLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseProfileLine(%q) = nil error, want error", tt.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProfileLine(%q) error: %v", tt.line, err)
			}
			if file != tt.wantFile || stmts != tt.wantStmts || count != tt.wantCount {
				t.Errorf("got (%q, %d, %d), want (%q, %d, %d)",
					file, stmts, count, tt.wantFile, tt.wantStmts, tt.wantCount)
			}
		})
	}
}

func TestThresholdForPrefersLongestPrefix(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Total: 75,
		Packages: map[string]float64{
			"internal/store":      80,
			"internal/store/sqlc": 10,
			"internal/policy":     90,
		},
	}

	tests := []struct {
		pkg  string
		want float64
	}{
		{"internal/policy", 90},
		{"internal/store", 80},
		{"internal/store/migrations", 80},
		{"internal/store/sqlc", 10},
		{"internal/store/sqlc/nested", 10},
		{"internal/smtpsrv", 75},
		// A prefix must align on a path separator: "internal/policyx" is a
		// different package and must not inherit the policy threshold.
		{"internal/policyx", 75},
	}

	for _, tt := range tests {
		if got := thresholdFor(tt.pkg, cfg); got != tt.want {
			t.Errorf("thresholdFor(%q) = %v, want %v", tt.pkg, got, tt.want)
		}
	}
}

func TestIsExcluded(t *testing.T) {
	t.Parallel()

	exclude := []string{"internal/tools", "cmd/smtp-auth-proxy"}
	cases := map[string]bool{
		"internal/tools":            true,
		"internal/tools/covercheck": true,
		"internal/toolsmith":        false,
		"cmd/smtp-auth-proxy":       true,
		"internal/policy":           false,
	}
	for pkg, want := range cases {
		if got := isExcluded(pkg, exclude); got != want {
			t.Errorf("isExcluded(%q) = %v, want %v", pkg, got, want)
		}
	}
}

func TestPkgStatsPercent(t *testing.T) {
	t.Parallel()

	// An empty package counts as fully covered rather than 0%, so that adding a
	// file with no statements cannot fail the build.
	if got := (pkgStats{}).percent(); got != 100 {
		t.Errorf("empty package percent = %v, want 100", got)
	}
	if got := (pkgStats{total: 4, covered: 3}).percent(); got != 75 {
		t.Errorf("percent = %v, want 75", got)
	}
}

func TestReportFailsBelowThreshold(t *testing.T) {
	t.Parallel()

	cfg := Config{Total: 75, Packages: map[string]float64{"internal/policy": 90}}
	stats := map[string]*pkgStats{
		"internal/policy":  {total: 10, covered: 8}, // 80% < 90%
		"internal/smtpsrv": {total: 10, covered: 9},
	}

	err := report(stats, cfg)
	if err == nil {
		t.Fatal("report() = nil, want failure for internal/policy")
	}
	if !strings.Contains(err.Error(), "internal/policy") {
		t.Errorf("error should name the failing package, got: %v", err)
	}
	if strings.Contains(err.Error(), "internal/smtpsrv") {
		t.Errorf("error should not name a passing package, got: %v", err)
	}
}

func TestReportPassesAtExactThreshold(t *testing.T) {
	t.Parallel()

	cfg := Config{Total: 75, Packages: map[string]float64{"internal/policy": 90}}
	stats := map[string]*pkgStats{
		"internal/policy": {total: 10, covered: 9}, // exactly 90%
	}
	if err := report(stats, cfg); err != nil {
		t.Errorf("report() at exact threshold = %v, want nil", err)
	}
}
