package core_test

// Replays the signer section of the Web Bot Auth -01 Signature-Agent corpus
// (sdk/go/helpers/testdata/wba-signature-agent-vectors.json) through the real
// signing transport: a transport configured with each value sends the recorded
// Signature-Agent, which verifies as the recorded key directory, or it refuses the
// request with the recorded refusal and nothing reaches the base transport.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

type wbaSignerRow struct {
	Name                 string `json:"name"`
	Configured           string `json:"configured"`
	SignatureAgent       string `json:"signature_agent"`
	ExpectedKeyDirectory string `json:"expected_key_directory"`
	ExpectedRefusal      string `json:"expected_refusal"`
}

// wbaSignerRefusals binds each signer refusal token to the Go sentinel a caller
// matches it with.
var wbaSignerRefusals = map[string]error{
	"signature_agent_required":          helpers.ErrSignatureAgentRequired,
	"signature_agent_not_origin":        helpers.ErrSignatureAgentNotOrigin,
	"signature_agent_not_key_directory": helpers.ErrSignatureAgentNotKeyDirectory,
}

func TestSigningTransport_ReplaysTheWBASignerCorpus(t *testing.T) {
	t.Parallel()
	rows := loadWBASignerRows(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer("agent.v1", priv)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().Unix()
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{signer.KeyID(): pub})
	for _, r := range rows {
		t.Run(r.Name, func(t *testing.T) { replayWBASignerRow(t, signer, resolver, created, r) })
	}
}

// replayWBASignerRow signs through a transport configured with the row's value and
// holds what it sends, or its refusal, to the row.
func replayWBASignerRow(
	t *testing.T,
	signer helpers.Signer,
	resolver helpers.KeyResolver,
	created int64,
	r wbaSignerRow,
) {
	t.Helper()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(signer, cap, core.WithSignatureAgent(r.Configured),
		core.WithWindow(fixedWindow(created, created+60)))
	err := roundTrip(tr, bodiedRequest(t, "/fora.v1.ExchangeService/DiscoverResources"))
	if r.ExpectedRefusal == "" {
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		assertSentKeyDirectory(t, cap.req, resolver, created, r)
		return
	}
	if want := wbaSignerRefusals[r.ExpectedRefusal]; want == nil || !errors.Is(err, want) {
		t.Fatalf("RoundTrip error = %v, want refusal %q", err, r.ExpectedRefusal)
	}
	if cap.req != nil {
		t.Error("a refused request reached the base transport")
	}
}

// loadWBASignerRows reads the signer section of the Web Bot Auth -01 corpus.
func loadWBASignerRows(t *testing.T) []wbaSignerRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "helpers", "testdata", "wba-signature-agent-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Signer []wbaSignerRow `json:"signer"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Signer) == 0 {
		t.Fatal("the corpus has no signer rows")
	}
	return doc.Signer
}

// roundTrip sends req through tr and closes any response body.
func roundTrip(tr http.RoundTripper, req *http.Request) error {
	resp, err := tr.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

// assertSentKeyDirectory holds the request the transport sent to the row's
// Signature-Agent, and verifies it as the row's key directory.
func assertSentKeyDirectory(
	t *testing.T,
	sent *http.Request,
	resolver helpers.KeyResolver,
	created int64,
	r wbaSignerRow,
) {
	t.Helper()
	if got := sent.Header.Get(helpers.SignatureAgentHeader); got != r.SignatureAgent {
		t.Fatalf("Signature-Agent = %q, want %q", got, r.SignatureAgent)
	}
	vr, err := helpers.VerifyRequestResolved(context.Background(), sent, []byte(`{"test":true}`),
		resolver, helpers.VerifyOptions{Now: time.Unix(created, 0)})
	if err != nil {
		t.Fatalf("the verifier refuses what the transport sent: %v", err)
	}
	if vr.KeyDirectory != r.ExpectedKeyDirectory {
		t.Errorf("KeyDirectory = %q, want %q", vr.KeyDirectory, r.ExpectedKeyDirectory)
	}
}
