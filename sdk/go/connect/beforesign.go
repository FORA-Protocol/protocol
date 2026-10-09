package connect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// BeforeSign is the pre-signing hook. It receives every RPC request the client is
// about to sign — built, stamped and (under ValidationStrict) validated — and
// returns the request to sign and send instead. A test that must send a
// deliberately altered message patches it here; the SDK then signs exactly the
// bytes the hook returned, and decodes the reply with its own decoder, so the hook
// is never a way around signing or decoding.
//
// The request handed in is the caller's to change. Its body has already been read
// into memory, so the hook may read it, and a body the hook replaces is what the
// Content-Digest covers. Refused, with nothing sent, as CallMalformed: a hook that
// returns an error or a nil request; one that changes the method or the URL (the
// address checks and the routing were decided on them); and one that sets or
// changes a header the signer writes. A Host or Content-Length the hook sets never
// reaches the peer — both are recomputed from the request itself.
type BeforeSign func(*http.Request) (*http.Request, error)

// WithBeforeSign installs a pre-signing hook on every leg that signs: the home
// Exchange, the Broker, the Exchange an offer named, the catalog and the admin
// clients. The delivery fetch is a GET with no body to alter and does not run it.
func WithBeforeSign(hook BeforeSign) ClientOption {
	return func(c *clientConfig) { c.beforeSign = hook }
}

// signerHeaders are the headers helpers.SignRequest writes: the three that carry
// the signature and the digest, and the two covered headers it fills when the
// request lacks them. A hook that set any of them would either be overwritten
// silently or contradict the signature, so it is refused instead.
var signerHeaders = []string{"Signature", "Signature-Input", "Content-Digest", "Signature-Agent", "Authorization"}

// beforeSignError marks a refusal of the hook, so sendError reports it as malformed
// rather than as a peer that did not answer — the classification connect-go gives
// any error a transport returns.
type beforeSignError struct{ err error }

func (e *beforeSignError) Error() string { return "before sign: " + e.err.Error() }
func (e *beforeSignError) Unwrap() error { return e.err }

// beforeSignTransport runs the hook immediately before the signing transport.
type beforeSignTransport struct {
	hook BeforeSign
	next http.RoundTripper
}

func (t beforeSignTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	patched, err := t.apply(req)
	if err != nil {
		return nil, &beforeSignError{err: err}
	}
	return t.next.RoundTrip(patched)
}

// apply hands the hook a copy of req whose body is readable, then checks and
// normalizes what it returned.
func (t beforeSignTransport) apply(req *http.Request) (*http.Request, error) {
	body, err := readBody(req.Body)
	if err != nil {
		return nil, fmt.Errorf("read the request body: %w", err)
	}
	handed := req.Clone(req.Context())
	setBody(handed, body)
	before := handed.Header.Clone()
	returned, err := t.hook(handed)
	if err != nil {
		return nil, err
	}
	if returned == nil {
		return nil, errors.New("the hook returned no request")
	}
	if returned.Method != req.Method || returned.URL.String() != req.URL.String() {
		return nil, errors.New("the hook must not change the request method or URL")
	}
	if clash := signerOwned(before, returned.Header); len(clash) > 0 {
		return nil, fmt.Errorf("the hook set headers the signer owns: %s", strings.Join(clash, ", "))
	}
	newBody, err := readBody(returned.Body)
	if err != nil {
		return nil, fmt.Errorf("read the hook's request body: %w", err)
	}
	out := req.Clone(req.Context())
	out.Header = returned.Header.Clone()
	out.Header.Del("Host")
	out.Header.Del("Content-Length")
	setBody(out, newBody)
	return out, nil
}

// signerOwned names every signer header whose value the hook changed.
func signerOwned(before, after http.Header) []string {
	var clash []string
	for _, name := range signerHeaders {
		if strings.Join(before.Values(name), ",") != strings.Join(after.Values(name), ",") {
			clash = append(clash, name)
		}
	}
	sort.Strings(clash)
	return clash
}

func readBody(body io.ReadCloser) ([]byte, error) {
	if body == nil || body == http.NoBody {
		return nil, nil
	}
	defer func() { _ = body.Close() }()
	return io.ReadAll(body)
}

func setBody(req *http.Request, body []byte) {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))
}
