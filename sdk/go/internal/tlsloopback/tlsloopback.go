// Package tlsloopback gives a test the client of an in-process TLS server, which is
// how the SDK's suites reach a loopback peer.
//
// The SDK dials https only and refuses loopback addresses, and no switch turns either
// check off. A suite that drives a fetch against an httptest server therefore serves
// it with httptest.NewTLSServer and injects a client that trusts that server, through
// the same option a deployment uses to reach a private peer. Every httptest TLS server
// presents the same test certificate, so one trusting client reaches all of them.
//
// It is test support, imported only by _test.go files. Like vectorio it takes no
// *testing.T: a non-test package that imports testing registers the -test.* flags on
// every binary that links it.
package tlsloopback

import (
	"net/http"
	"net/http/httptest"
)

// Client returns a new unguarded client that trusts every httptest TLS server. It is
// taken from a throwaway server that is closed before Client returns; the client
// keeps the trusted certificate and stays usable.
func Client() *http.Client {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	return srv.Client()
}
