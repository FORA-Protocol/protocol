package resolvers_test

// The key directory under the Web Bot Auth profile, through WBAKeyResolver: only
// a key the response is signed by is handed out, the media type is the profile's,
// a redirect fails the fetch, and a request carrying two signatures has each one
// resolved in the directory its own Signature-Agent member names.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

func profileResolver(client *http.Client) *resolvers.WBAKeyResolver {
	return resolvers.NewWBAKeyResolver(resolvers.WBAKeyResolverOptions{
		Scheme: "http", HTTP: client, Now: func() time.Time { return wbaAnchor },
	})
}

// TestWBAKeyResolver_handsOutOnlyKeysThatSignedTheResponse: a listed key with no
// valid response signature is never resolved.
func TestWBAKeyResolver_handsOutOnlyKeysThatSignedTheResponse(t *testing.T) {
	t.Parallel()
	signedPriv, signedJWK := newSigningKey("signed", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	// A key whose private half no test registered, so the origin cannot sign with it.
	unsignedPub, _, _ := ed25519.GenerateKey(nil)
	_, unsignedJWK := newSigningKey("unsigned-placeholder", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	unsignedJWK.X = jwkX(unsignedPub)

	origin := newWBAOrigin(nil)
	defer origin.close()
	origin.setWBA(marshalWBA(signedJWK, unsignedJWK))
	r := profileResolver(origin.Client())
	ctx := helpers.WithSignatureAgent(context.Background(), origin.url)

	if _, err := r.Resolve(ctx, mustThumbprint(t, signedPriv.Public().(ed25519.PublicKey))); err != nil {
		t.Fatalf("the signing key: %v", err)
	}
	if _, err := r.Resolve(ctx, mustThumbprint(t, unsignedPub)); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("a key that did not sign the response: err = %v, want ErrUnknownKey", err)
	}
}

// TestWBAKeyResolver_refusesTheWrongMediaTypeAndRedirects: a directory served as
// application/jwk-set+json, or reached through a redirect, is a directory that is
// unavailable, never one whose keys are read.
func TestWBAKeyResolver_refusesTheWrongMediaTypeAndRedirects(t *testing.T) {
	t.Parallel()
	priv, jwk := newSigningKey("k-media", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	tp := mustThumbprint(t, priv.Public().(ed25519.PublicKey))
	body := marshalWBA(jwk)
	for name, handler := range map[string]http.HandlerFunc{
		"the JWK Set media type": func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			writeSignedDirectory(rec, r, body)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.Header().Set("Content-Type", "application/jwk-set+json")
			_, _ = w.Write(rec.Body.Bytes())
		},
		"a redirect": func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/moved") {
				writeSignedDirectory(w, r, body)
				return
			}
			http.Redirect(w, r, "/moved", http.StatusFound)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			ctx := helpers.WithSignatureAgent(context.Background(), srv.URL)
			if _, err := profileResolver(srv.Client()).Resolve(ctx, tp); !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
				t.Fatalf("err = %v, want ErrDirectoryUnavailable", err)
			}
		})
	}
}

// TestWBAKeyResolver_eachSignatureInItsOwnDirectory signs one request as an agent
// and a broker, each publishing its key only in its own directory, and verifies
// both signatures through one resolver. Swapping which member the broker's
// signature covers sends its keyid to the agent's directory, where it is unknown.
func TestWBAKeyResolver_eachSignatureInItsOwnDirectory(t *testing.T) {
	t.Parallel()
	agentPriv, agentJWK := newSigningKey("agent-dir", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	brokerPriv, brokerJWK := newSigningKey("broker-dir", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	agentOrigin, brokerOrigin := newWBAOrigin(nil), newWBAOrigin(nil)
	defer agentOrigin.close()
	defer brokerOrigin.close()
	agentOrigin.setWBA(marshalWBA(agentJWK))
	brokerOrigin.setWBA(marshalWBA(brokerJWK))
	httpsOrigin := func(o *wbaOrigin) string { return "https://" + strings.TrimPrefix(o.url, "http://") }

	signer := func(priv ed25519.PrivateKey) helpers.Signer {
		s, err := helpers.NewEd25519Signer(mustThumbprint(t, priv.Public().(ed25519.PublicKey)), priv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	body := []byte(`{"q":"two directories"}`)
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/fora.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	created := wbaAnchor.Unix()
	opts := func(origin string) helpers.SignOptions {
		return helpers.SignOptions{Created: created, Expires: created + 300, SignatureAgent: origin}
	}
	if err := helpers.SignRequest(context.Background(), req, body, signer(agentPriv), opts(httpsOrigin(agentOrigin))); err != nil {
		t.Fatal(err)
	}
	if err := helpers.AppendSignature(context.Background(), req, body, signer(brokerPriv), opts(httpsOrigin(brokerOrigin))); err != nil {
		t.Fatal(err)
	}
	r := profileResolver(http.DefaultClient)
	vopts := helpers.VerifyOptions{Now: wbaAnchor.Add(time.Minute)}
	verified, err := helpers.VerifyMultisigRequestResolved(context.Background(), req, body, r, vopts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verified) != 2 || verified[0].SignatureAgent != httpsOrigin(agentOrigin) || verified[1].SignatureAgent != httpsOrigin(brokerOrigin) {
		t.Fatalf("verified = %+v", verified)
	}

	// Point sig2's member at the agent's directory: its signature no longer
	// verifies, and nothing resolves the broker's key from the agent's directory.
	swapped := req.Clone(context.Background())
	swapped.Header.Set(helpers.SignatureAgentHeader,
		`sig1="`+httpsOrigin(agentOrigin)+`", sig2="`+httpsOrigin(agentOrigin)+`"`)
	if _, err := helpers.VerifyMultisigRequestResolved(context.Background(), swapped, body, r, vopts); err == nil {
		t.Fatal("a broker signature verified after its member was pointed at the agent's directory")
	}
}

func jwkX(pub ed25519.PublicKey) string { return base64.RawURLEncoding.EncodeToString(pub) }
