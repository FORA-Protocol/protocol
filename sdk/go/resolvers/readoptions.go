package resolvers

import (
	"fmt"
	"net/http"
	"time"
)

// ReadOptions configures a document reader. The zero value reads over https
// through the SDK's guarded client.
type ReadOptions struct {
	// Client dials the document. Nil builds NewGuardedClient: the dial-time
	// SSRF guard refuses loopback, private and metadata addresses and the scheme
	// guard refuses anything but https. A caller that must reach a private or
	// plaintext origin injects its own client.
	Client *http.Client
	// Scheme is the scheme of a URL a reader builds from a domain. Only "" and
	// "https" are accepted; any other value fails the read with
	// ErrDirectoryUnavailable before anything is dialed.
	//
	// Deprecated: a URL a reader builds is always https, so leave Scheme empty.
	// Scheme is removed in 2.0.
	Scheme string
	// Now is the instant a key directory's response signatures are judged at; the
	// zero value is the wall clock at the read. Only ReadWBADirectory reads it, so a
	// ReadOptions built once and reused leaves it zero.
	Now time.Time
}

func (o ReadOptions) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return NewGuardedClient()
}

func (o ReadOptions) now() time.Time {
	if !o.Now.IsZero() {
		return o.Now
	}
	return time.Now()
}

// builtURL is https://domain + path, or the refusal of a Scheme that is not https.
func (o ReadOptions) builtURL(op, domain, path string) (string, error) {
	if err := refuseSchemeOption(o.Scheme); err != nil {
		return "", fmt.Errorf("resolvers: %s: %w: %w", op, ErrDirectoryUnavailable, err)
	}
	return "https://" + domain + path, nil
}
