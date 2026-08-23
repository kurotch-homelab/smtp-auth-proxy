package smtpsrv

import (
	"errors"
	"strings"
	"testing"
)

func TestLoginServerHappyPath(t *testing.T) {
	t.Parallel()

	var gotUser, gotPass string
	s := newLoginServer(func(username, password string) error {
		gotUser, gotPass = username, password
		return nil
	})

	// The client sends AUTH LOGIN with no initial response.
	challenge, done, err := s.Next(nil)
	if err != nil || done {
		t.Fatalf("first Next = (%q, %v, %v)", challenge, done, err)
	}
	if string(challenge) != "Username:" {
		t.Errorf("first challenge = %q, want Username:", challenge)
	}

	challenge, done, err = s.Next([]byte("svc-printer"))
	if err != nil || done {
		t.Fatalf("second Next = (%q, %v, %v)", challenge, done, err)
	}
	if string(challenge) != "Password:" {
		t.Errorf("second challenge = %q, want Password:", challenge)
	}

	if _, done, err = s.Next([]byte("s3cret")); err != nil || !done {
		t.Fatalf("third Next = (%v, %v), want done with no error", done, err)
	}
	if gotUser != "svc-printer" || gotPass != "s3cret" {
		t.Errorf("authenticator saw (%q, %q)", gotUser, gotPass)
	}
}

func TestLoginServerWithAnInitialResponse(t *testing.T) {
	t.Parallel()

	// Some clients send the username as the initial response.
	var gotUser string
	s := newLoginServer(func(username, _ string) error {
		gotUser = username
		return nil
	})

	challenge, done, err := s.Next([]byte("svc-printer"))
	if err != nil || done || string(challenge) != "Password:" {
		t.Fatalf("Next with an initial response = (%q, %v, %v)", challenge, done, err)
	}
	if _, done, err := s.Next([]byte("s3cret")); err != nil || !done {
		t.Fatalf("Next = (%v, %v)", done, err)
	}
	if gotUser != "svc-printer" {
		t.Errorf("username = %q", gotUser)
	}
}

func TestLoginServerPropagatesFailure(t *testing.T) {
	t.Parallel()

	s := newLoginServer(func(string, string) error { return ErrAuthFailed })

	if _, _, err := s.Next([]byte("user")); err != nil {
		t.Fatalf("username step: %v", err)
	}
	_, done, err := s.Next([]byte("wrong"))
	if !done || !errors.Is(err, ErrAuthFailed) {
		t.Errorf("Next = (%v, %v), want done with ErrAuthFailed", done, err)
	}
}

func TestLoginServerBoundsFieldLength(t *testing.T) {
	t.Parallel()

	called := false
	s := newLoginServer(func(string, string) error {
		called = true
		return nil
	})

	// An unauthenticated client must not be able to make the server hold or
	// hash an arbitrarily large buffer.
	huge := []byte(strings.Repeat("x", maxLoginFieldLen+1))
	if _, done, err := s.Next(huge); !done || err == nil {
		t.Errorf("an oversized username = (%v, %v), want a failure", done, err)
	}
	if called {
		t.Error("an oversized username reached the authenticator")
	}

	s2 := newLoginServer(func(string, string) error { return nil })
	if _, _, err := s2.Next([]byte("user")); err != nil {
		t.Fatalf("username step: %v", err)
	}
	if _, done, err := s2.Next(huge); !done || err == nil {
		t.Errorf("an oversized password = (%v, %v), want a failure", done, err)
	}
}

func TestLoginServerRejectsExtraSteps(t *testing.T) {
	t.Parallel()

	s := newLoginServer(func(string, string) error { return nil })

	if _, _, err := s.Next([]byte("user")); err != nil {
		t.Fatalf("username step: %v", err)
	}
	if _, _, err := s.Next([]byte("pass")); err != nil {
		t.Fatalf("password step: %v", err)
	}
	if _, _, err := s.Next([]byte("again")); err == nil {
		t.Error("a fourth step was accepted after the exchange finished")
	}
}
