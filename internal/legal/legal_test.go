package legal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHandler(t *testing.T) {
	want, err := os.ReadFile("THIRD_PARTY_NOTICES.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) == 0 {
		t.Fatal("license notices must not be empty")
	}
	for _, tc := range []struct {
		url         string
		disposition string
	}{
		{"/licenses", ""},
		{"/licenses?download=1", `attachment; filename="THIRD_PARTY_NOTICES.txt"`},
		{"/licenses?download=0", ""},
	} {
		t.Run(tc.url, func(t *testing.T) {
			response := httptest.NewRecorder()
			Handler(response, httptest.NewRequest(http.MethodGet, tc.url, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d", response.Code)
			}
			if response.Body.String() != string(want) {
				t.Fatal("response differs from distributed notices")
			}
			for key, value := range map[string]string{
				"Content-Type":           "text/plain; charset=utf-8",
				"X-Content-Type-Options": "nosniff",
				"Content-Disposition":    tc.disposition,
			} {
				if got := response.Header().Get(key); got != value {
					t.Errorf("%s = %q, want %q", key, got, value)
				}
			}
		})
	}
}
