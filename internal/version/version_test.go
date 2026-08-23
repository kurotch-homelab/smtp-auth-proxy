package version

import (
	"runtime/debug"
	"testing"
)

func TestGetPopulatesRuntimeFields(t *testing.T) {
	t.Parallel()

	got := Get()
	if got.Version == "" {
		t.Error("Version must never be empty")
	}
	if got.GoVersion == "" {
		t.Error("GoVersion must be populated from the runtime")
	}
	if got.Platform == "" {
		t.Error("Platform must be populated from the runtime")
	}
}

func TestApplyVCSSettings(t *testing.T) {
	t.Parallel()

	const longSHA = "0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name          string
		in            Info
		settings      []debug.BuildSetting
		wantCommit    string
		wantBuildDate string
	}{
		{
			name:          "fills unknown fields from VCS stamps",
			in:            Info{Commit: unknown, BuildDate: unknown},
			settings:      []debug.BuildSetting{{Key: "vcs.revision", Value: longSHA}, {Key: "vcs.time", Value: "2026-01-02T03:04:05Z"}},
			wantCommit:    "0123456789ab",
			wantBuildDate: "2026-01-02T03:04:05Z",
		},
		{
			name:          "linker-stamped values win over VCS stamps",
			in:            Info{Commit: "deadbeef", BuildDate: "2020-01-01"},
			settings:      []debug.BuildSetting{{Key: "vcs.revision", Value: longSHA}, {Key: "vcs.time", Value: "2026-01-02T03:04:05Z"}},
			wantCommit:    "deadbeef",
			wantBuildDate: "2020-01-01",
		},
		{
			name:          "short revisions are kept whole",
			in:            Info{Commit: unknown, BuildDate: unknown},
			settings:      []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}},
			wantCommit:    "abc123",
			wantBuildDate: unknown,
		},
		{
			name:          "empty values are ignored",
			in:            Info{Commit: unknown, BuildDate: unknown},
			settings:      []debug.BuildSetting{{Key: "vcs.revision", Value: ""}, {Key: "vcs.time", Value: ""}},
			wantCommit:    unknown,
			wantBuildDate: unknown,
		},
		{
			name:          "unrelated settings are ignored",
			in:            Info{Commit: unknown, BuildDate: unknown},
			settings:      []debug.BuildSetting{{Key: "GOARCH", Value: "arm64"}, {Key: "-tags", Value: "e2e"}},
			wantCommit:    unknown,
			wantBuildDate: unknown,
		},
		{
			name:          "no settings at all",
			in:            Info{Commit: unknown, BuildDate: unknown},
			settings:      nil,
			wantCommit:    unknown,
			wantBuildDate: unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := applyVCSSettings(tt.in, tt.settings)
			if got.Commit != tt.wantCommit {
				t.Errorf("Commit = %q, want %q", got.Commit, tt.wantCommit)
			}
			if got.BuildDate != tt.wantBuildDate {
				t.Errorf("BuildDate = %q, want %q", got.BuildDate, tt.wantBuildDate)
			}
		})
	}
}

func TestStringIncludesEveryField(t *testing.T) {
	t.Parallel()

	i := Info{Version: "v1.2.3", Commit: "abc123", BuildDate: "2026-01-01", GoVersion: "go1.24", Platform: "linux/amd64"}
	want := "v1.2.3 (commit abc123, built 2026-01-01, go1.24, linux/amd64)"
	if got := i.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestUserAgent(t *testing.T) {
	t.Parallel()

	if got := UserAgent(); got != "smtp-auth-proxy/"+Version {
		t.Errorf("UserAgent() = %q", got)
	}
}
