// Package version exposes build metadata stamped in at link time.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Values are overridden via -ldflags -X at build time; see the Makefile.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// unknown marks a field the linker did not stamp.
const unknown = "unknown"

// shortCommitLen is how much of a git SHA is kept for display.
const shortCommitLen = 12

// Info describes the running build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns the build metadata, falling back to the VCS stamps that `go
// build` embeds when the linker flags were not supplied (e.g. under `go run`).
func Get() Info {
	i := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		i = applyVCSSettings(i, bi.Settings)
	}
	return i
}

// applyVCSSettings fills in Commit and BuildDate from the build settings Go
// records for VCS-aware builds. Values already stamped by the linker win, so a
// release build never has its version metadata overwritten.
func applyVCSSettings(i Info, settings []debug.BuildSetting) Info {
	for _, s := range settings {
		if s.Value == "" {
			continue
		}
		switch s.Key {
		case "vcs.revision":
			if i.Commit == unknown {
				i.Commit = shortenCommit(s.Value)
			}
		case "vcs.time":
			if i.BuildDate == unknown {
				i.BuildDate = s.Value
			}
		}
	}
	return i
}

func shortenCommit(rev string) string {
	if len(rev) > shortCommitLen {
		return rev[:shortCommitLen]
	}
	return rev
}

// String renders the build metadata on a single line.
func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s, %s)",
		i.Version, i.Commit, i.BuildDate, i.GoVersion, i.Platform)
}

// UserAgent is the client identifier this build sends to upstream servers.
func UserAgent() string {
	return "smtp-auth-proxy/" + Version
}
