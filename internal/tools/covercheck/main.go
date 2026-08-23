// Command covercheck enforces per-package coverage thresholds against a Go
// coverage profile. It exists because `go test -cover` can only report a single
// global number, while the packages that carry the security-relevant logic in
// this project need a stricter bar than the wiring around them.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config mirrors .coverage.yaml.
type Config struct {
	Total    float64            `yaml:"total"`
	Packages map[string]float64 `yaml:"packages"`
	Exclude  []string           `yaml:"exclude"`
}

// pkgStats accumulates statement counts for one package.
type pkgStats struct {
	total   int
	covered int
}

func (p pkgStats) percent() float64 {
	if p.total == 0 {
		return 100
	}
	return float64(p.covered) / float64(p.total) * 100
}

func main() {
	var (
		profilePath = flag.String("profile", "coverage.out", "path to the Go coverage profile")
		configPath  = flag.String("config", ".coverage.yaml", "path to the threshold config")
	)
	flag.Parse()

	if err := run(*profilePath, *configPath); err != nil {
		fmt.Fprintf(os.Stderr, "covercheck: %v\n", err)
		os.Exit(1)
	}
}

func run(profilePath, configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	f, err := os.Open(profilePath)
	if err != nil {
		return fmt.Errorf("open profile: %w", err)
	}
	defer f.Close()

	module, err := moduleFromProfile(profilePath)
	if err != nil {
		return err
	}

	stats, err := parseProfile(f, module, cfg.Exclude)
	if err != nil {
		return err
	}
	if len(stats) == 0 {
		return errors.New("profile contained no packages after exclusions")
	}

	return report(stats, cfg)
}

func loadConfig(p string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(p)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// moduleFromProfile reads the module path from go.mod so profile entries, which
// are module-qualified, can be shortened to repository-relative paths.
func moduleFromProfile(profilePath string) (string, error) {
	dir := path.Dir(profilePath)
	for range 5 {
		b, err := os.ReadFile(path.Join(dir, "go.mod"))
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if after, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
					return strings.TrimSpace(after), nil
				}
			}
			return "", errors.New("go.mod has no module directive")
		}
		dir = path.Join(dir, "..")
	}
	return "", errors.New("could not locate go.mod")
}

func parseProfile(r *os.File, module string, exclude []string) (map[string]*pkgStats, error) {
	stats := map[string]*pkgStats{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for lineNo := 0; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		file, stmts, count, err := parseProfileLine(line)
		if err != nil {
			return nil, fmt.Errorf("profile line %d: %w", lineNo+1, err)
		}

		pkg := strings.TrimPrefix(path.Dir(file), module+"/")
		if isExcluded(pkg, exclude) {
			continue
		}
		s, ok := stats[pkg]
		if !ok {
			s = &pkgStats{}
			stats[pkg] = s
		}
		s.total += stmts
		if count > 0 {
			s.covered += stmts
		}
	}
	return stats, sc.Err()
}

// parseProfileLine splits `path/file.go:1.2,3.4 5 6` into its file, statement
// count and execution count.
func parseProfileLine(line string) (file string, stmts, count int, err error) {
	colon := strings.LastIndex(line, ":")
	if colon < 0 {
		return "", 0, 0, errors.New("missing ':' separator")
	}
	file = line[:colon]

	fields := strings.Fields(line[colon+1:])
	if len(fields) != 3 {
		return "", 0, 0, fmt.Errorf("expected 3 fields after ':', got %d", len(fields))
	}
	if stmts, err = strconv.Atoi(fields[1]); err != nil {
		return "", 0, 0, fmt.Errorf("statement count: %w", err)
	}
	if count, err = strconv.Atoi(fields[2]); err != nil {
		return "", 0, 0, fmt.Errorf("execution count: %w", err)
	}
	return file, stmts, count, nil
}

func isExcluded(pkg string, exclude []string) bool {
	for _, e := range exclude {
		if pkg == e || strings.HasPrefix(pkg, e+"/") {
			return true
		}
	}
	return false
}

// thresholdFor returns the required percentage for a package, preferring the
// longest matching prefix so nested packages can override their parent.
func thresholdFor(pkg string, cfg Config) float64 {
	best, bestLen := cfg.Total, -1
	for prefix, want := range cfg.Packages {
		if pkg != prefix && !strings.HasPrefix(pkg, prefix+"/") {
			continue
		}
		if len(prefix) > bestLen {
			best, bestLen = want, len(prefix)
		}
	}
	return best
}

func report(stats map[string]*pkgStats, cfg Config) error {
	pkgs := make([]string, 0, len(stats))
	overall := pkgStats{}
	for p, s := range stats {
		pkgs = append(pkgs, p)
		overall.total += s.total
		overall.covered += s.covered
	}
	sort.Strings(pkgs)

	width := len("TOTAL")
	for _, p := range pkgs {
		width = max(width, len(p))
	}

	var failures []string
	for _, p := range pkgs {
		got, want := stats[p].percent(), thresholdFor(p, cfg)
		status := "ok"
		if got+1e-9 < want {
			status = "FAIL"
			failures = append(failures, fmt.Sprintf("%s: %.1f%% < %.1f%%", p, got, want))
		}
		fmt.Printf("%-*s  %6.1f%%  (need %5.1f%%)  %s\n", width, p, got, want, status)
	}

	fmt.Printf("%-*s  %6.1f%%  (need %5.1f%%)\n", width, "TOTAL", overall.percent(), cfg.Total)
	if overall.percent()+1e-9 < cfg.Total {
		failures = append(failures, fmt.Sprintf("total: %.1f%% < %.1f%%", overall.percent(), cfg.Total))
	}

	if len(failures) > 0 {
		return fmt.Errorf("coverage below threshold:\n  %s", strings.Join(failures, "\n  "))
	}
	return nil
}
