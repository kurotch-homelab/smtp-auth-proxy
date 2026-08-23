package smtpsrv

import (
	"errors"

	"github.com/emersion/go-sasl"
)

// AUTH LOGIN is not a standardized SASL mechanism and go-sasl deliberately does
// not ship a server for it. It is implemented here anyway because a large share
// of the devices this proxy exists for — multifunction printers, older NAS
// firmware, embedded monitoring agents — support nothing else.
//
// The exchange is two base64-encoded prompts:
//
//	S: 334 VXNlcm5hbWU6      ("Username:")
//	C: <base64 username>
//	S: 334 UGFzc3dvcmQ6      ("Password:")
//	C: <base64 password>
//
// go-smtp handles the base64 layer, so this only sees and returns raw bytes.

// loginAuthenticator verifies a username and password pair.
type loginAuthenticator func(username, password string) error

// loginState is which prompt the exchange is waiting on.
type loginState int

const (
	loginStateUsername loginState = iota
	loginStatePassword
	loginStateDone
)

// Prompts are sent verbatim; clients match on them loosely, and these are the
// spellings every implementation recognizes.
var (
	usernameChallenge = []byte("Username:")
	passwordChallenge = []byte("Password:")
)

// maxLoginFieldLen bounds a username or password before it reaches the
// authenticator, so an unauthenticated client cannot make the server hold or
// hash a large buffer.
const maxLoginFieldLen = 1024

type loginServer struct {
	authenticate loginAuthenticator
	state        loginState
	username     string
}

// newLoginServer returns a SASL server implementing AUTH LOGIN.
func newLoginServer(auth loginAuthenticator) sasl.Server {
	return &loginServer{authenticate: auth}
}

func (s *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.state {
	case loginStateUsername:
		// A client may send AUTH LOGIN with no initial response, in which case
		// response is nil and the username prompt has not been answered yet.
		if response == nil {
			return usernameChallenge, false, nil
		}
		if len(response) > maxLoginFieldLen {
			s.state = loginStateDone
			return nil, true, ErrAuthFailed
		}
		s.username = string(response)
		s.state = loginStatePassword
		return passwordChallenge, false, nil

	case loginStatePassword:
		if len(response) > maxLoginFieldLen {
			s.state = loginStateDone
			return nil, true, ErrAuthFailed
		}
		s.state = loginStateDone
		if err := s.authenticate(s.username, string(response)); err != nil {
			return nil, true, err
		}
		return nil, true, nil

	case loginStateDone:
		return nil, true, errors.New("smtpsrv: AUTH LOGIN exchange already finished")

	default:
		return nil, true, errors.New("smtpsrv: invalid AUTH LOGIN state")
	}
}
