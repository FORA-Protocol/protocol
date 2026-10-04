package connect_test

// Minting a fresh agent identity end to end: a key from helpers.GenerateKey, the
// directory document helpers.DirectoryDocument builds for it, served by an
// in-process origin, and a signing transport from core.SigningTransportFor. The
// verifier is the SDK's own server verify face resolving the key through the WBA
// directory the covered Signature-Agent names — the lookup an Exchange runs — so the
// test proves a verifier can find the minted key, not only that a request was signed.

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

func TestIdentityHelpers_MintAFreshAgent(t *testing.T) {
	priv, keyID, err := helpers.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if want, _ := helpers.Thumbprint(pub); keyID != want {
		t.Fatalf("keyid = %q, want the key's thumbprint %q", keyID, want)
	}

	now := time.Now()
	doc := helpers.DirectoryDocument([]ed25519.PublicKey{pub}, 0, now)
	jwk := doc.GetKeys()[0]
	if jwk.GetKty() != "OKP" || jwk.GetCrv() != "Ed25519" || jwk.GetAlg() != "EdDSA" || jwk.GetUse() != "sig" {
		t.Errorf("key = %v", jwk)
	}
	if notAfter, _ := time.Parse(time.RFC3339, jwk.GetNotAfter()); notAfter.Sub(now) < helpers.DefaultKeyValidity-time.Second {
		t.Errorf("not_after = %s, want DefaultKeyValidity from now", jwk.GetNotAfter())
	}
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatal(err)
	}
	// The directory answers as the profile requires: its own media type, and a
	// response signed by the key it lists for the authority it was fetched from.
	directory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig, err := helpers.SignDirectoryResponse(r.Context(), r.Host, body, []helpers.Signer{signer},
			now.Unix(), now.Add(time.Hour).Unix())
		if err != nil {
			t.Errorf("sign directory response: %v", err)
		}
		sig.Apply(w.Header())
		w.Header().Set("Content-Type", resolvers.WBADirectoryMediaType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(directory.Close)
	// The Signature-Agent member is an https origin; the resolver fetches it from
	// the plaintext test server through its Scheme option.
	origin := "https://" + strings.TrimPrefix(directory.URL, "http://")

	keys := resolvers.NewWBAKeyResolver(resolvers.WBAKeyResolverOptions{Scheme: "http", HTTP: http.DefaultClient})
	path, h := foraserver.NewCatalogServiceHandler(&recordingCatalog{}, foraserver.WithKeyResolver(keys))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	exchange := httptest.NewServer(mux)
	t.Cleanup(exchange.Close)

	transport, err := core.SigningTransportFor(priv, origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := forav1connect.NewCatalogServiceClient(&http.Client{Transport: transport}, exchange.URL)
	resp, err := client.RefreshCatalog(context.Background(), connectrpc.NewRequest(&forav1.RefreshCatalogRequest{
		Ver: helpers.ProtocolVersion, Exchange: "exchange.test", TenantId: "tenant-1"}))
	if err != nil {
		t.Fatalf("the verifier refused the minted identity: %v", err)
	}
	if !resp.Msg.GetStarted() {
		t.Errorf("answer = %v", resp.Msg)
	}

	if _, err := core.SigningTransportFor(priv[:10], origin, nil); err == nil {
		t.Error("a truncated key was accepted")
	}
}
