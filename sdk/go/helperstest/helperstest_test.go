package helperstest_test

// The test signers reproduce what the shared corpora record for "a signer without the
// check", answer exactly as the signers they twin for every other input, and produce
// nothing a production verifier accepts.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/helperstest"
)

type acceptanceRow struct {
	Name            string `json:"name"`
	Empty           string `json:"empty"`
	OfferSig        string `json:"offer_sig"`
	RequesterID     string `json:"requester_id"`
	RequesterDomain string `json:"requester_domain"`
	IdempotencyKey  string `json:"idempotency_key"`
	CanonicalJCS    string `json:"canonical_jcs"`
	SignatureHex    string `json:"signature_hex"`
	SeedHex         string `json:"seed_hex"`
}

func (r acceptanceRow) inputs() (*forav1.Offer, *forav1.Requester) {
	return &forav1.Offer{Signature: r.OfferSig}, &forav1.Requester{Id: r.RequesterID, Domain: r.RequesterDomain}
}

type requestRow struct {
	Name  string `json:"name"`
	Empty string `json:"empty"`
	Items []struct {
		OfferSig string `json:"offer_sig"`
		Exchange string `json:"exchange"`
	} `json:"items"`
	RequesterID     string `json:"requester_id"`
	RequesterDomain string `json:"requester_domain"`
	IdempotencyKey  string `json:"idempotency_key"`
	CanonicalJCS    string `json:"canonical_jcs"`
	SignatureHex    string `json:"signature_hex"`
	SeedHex         string `json:"seed_hex"`
}

func (r requestRow) request() *forav1.TransactionRequest {
	req := &forav1.TransactionRequest{
		Requester:      &forav1.Requester{Id: r.RequesterID, Domain: r.RequesterDomain},
		IdempotencyKey: r.IdempotencyKey,
	}
	for _, it := range r.Items {
		req.Items = append(req.Items, &forav1.TransactionItem{
			Offer: &forav1.Offer{Signature: it.OfferSig, Exchange: it.Exchange},
		})
	}
	return req
}

func (r requestRow) payload() *forav1.AgentRequestAcceptancePayload {
	p := &forav1.AgentRequestAcceptancePayload{
		RequesterId: r.RequesterID, RequesterDomain: r.RequesterDomain, IdempotencyKey: r.IdempotencyKey,
	}
	for _, it := range r.Items {
		p.Items = append(p.Items, &forav1.AgentRequestAcceptanceItem{OfferSig: it.OfferSig, Exchange: it.Exchange})
	}
	return p
}

type corpus[T any] struct {
	Vectors []T `json:"vectors"`
	Refused []T `json:"refused"`
}

func load[T any](t *testing.T, name string) corpus[T] {
	t.Helper()
	path := filepath.Join("..", "helpers", "testdata", name)
	raw, err := os.ReadFile(path) //nolint:gosec // a committed test vector
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var c corpus[T]
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(c.Vectors) == 0 || len(c.Refused) == 0 {
		t.Fatalf("%s carries %d vectors and %d refused rows; both are needed", path, len(c.Vectors), len(c.Refused))
	}
	return c
}

func keyOf(t *testing.T, seedHex string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func TestTheRefusedOfferAcceptancesAreReproduced(t *testing.T) {
	empties := map[string]bool{}
	for _, row := range load[acceptanceRow](t, "acceptance-vectors.json").Refused {
		t.Run(row.Name, func(t *testing.T) {
			priv, pub := keyOf(t, row.SeedHex)
			offer, requester := row.inputs()
			canonical, err := helperstest.CanonicalAcceptanceBytesAnyRequester(offer, requester, row.IdempotencyKey)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if string(canonical) != row.CanonicalJCS {
				t.Errorf("bytes = %s, want %s", canonical, row.CanonicalJCS)
			}
			sig, err := helperstest.SignOfferAcceptanceAnyRequester(priv, offer, requester, row.IdempotencyKey)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if sig != row.SignatureHex {
				t.Errorf("signature = %s, want %s", sig, row.SignatureHex)
			}
			// The signature verifies over those bytes, and the protocol's own verifier
			// and signer refuse them anyway: the empty requester is the one fault.
			raw, _ := hex.DecodeString(sig)
			if !ed25519.Verify(pub, canonical, raw) {
				t.Error("the signature does not verify over the bytes it signs")
			}
			if err := helpers.VerifyOfferAcceptance(offer, requester, row.IdempotencyKey, sig, pub); !errors.Is(err, helpers.ErrAcceptanceRequesterEmpty) {
				t.Errorf("VerifyOfferAcceptance = %v, want ErrAcceptanceRequesterEmpty", err)
			}
			if _, err := helpers.SignOfferAcceptance(priv, offer, requester, row.IdempotencyKey); !errors.Is(err, helpers.ErrAcceptanceRequesterEmpty) {
				t.Errorf("SignOfferAcceptance = %v, want ErrAcceptanceRequesterEmpty", err)
			}
		})
		empties[row.Empty] = true
	}
	if !empties["requester_id"] || !empties["requester_domain"] {
		t.Errorf("the refused rows cover %v; both requester fields are needed", empties)
	}
}

func TestTheRefusedRequestAcceptancesAreReproduced(t *testing.T) {
	empties := map[string]bool{}
	for _, row := range load[requestRow](t, "request-acceptance-vectors.json").Refused {
		t.Run(row.Name, func(t *testing.T) {
			priv, pub := keyOf(t, row.SeedHex)
			canonical, err := helperstest.CanonicalRequestAcceptanceBytesAnyRequester(row.payload())
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if string(canonical) != row.CanonicalJCS {
				t.Errorf("bytes = %s, want %s", canonical, row.CanonicalJCS)
			}
			acceptance, err := helperstest.SignRequestAcceptanceAnyRequester(priv, row.request())
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if acceptance.GetSignature() != row.SignatureHex {
				t.Errorf("signature = %s, want %s", acceptance.GetSignature(), row.SignatureHex)
			}
			if !proto.Equal(acceptance.GetPayload(), row.payload()) {
				t.Errorf("payload = %v, want %v", acceptance.GetPayload(), row.payload())
			}
			if acceptance.GetSignatureAlgorithm() != helpers.AcceptanceSignatureAlgorithm {
				t.Errorf("algorithm = %q, want %q", acceptance.GetSignatureAlgorithm(), helpers.AcceptanceSignatureAlgorithm)
			}
			if _, err := helpers.VerifyRequestAcceptance(row.request(), acceptance, pub); !errors.Is(err, helpers.ErrAcceptanceRequesterEmpty) {
				t.Errorf("VerifyRequestAcceptance = %v, want ErrAcceptanceRequesterEmpty", err)
			}
			if _, err := helpers.SignRequestAcceptance(priv, row.request()); !errors.Is(err, helpers.ErrAcceptanceRequesterEmpty) {
				t.Errorf("SignRequestAcceptance = %v, want ErrAcceptanceRequesterEmpty", err)
			}
		})
		empties[row.Empty] = true
	}
	if !empties["requester_id"] || !empties["requester_domain"] {
		t.Errorf("the refused rows cover %v; both requester fields are needed", empties)
	}
}

// On a requester that is named, the twins are the signers: same bytes, same signature.
func TestTheTwinsMatchTheSignersOnANamedRequester(t *testing.T) {
	for _, row := range load[acceptanceRow](t, "acceptance-vectors.json").Vectors {
		priv, _ := keyOf(t, row.SeedHex)
		offer, requester := row.inputs()
		want, wantErr := helpers.SignOfferAcceptance(priv, offer, requester, row.IdempotencyKey)
		got, err := helperstest.SignOfferAcceptanceAnyRequester(priv, offer, requester, row.IdempotencyKey)
		if wantErr != nil || err != nil || got != want || got != row.SignatureHex {
			t.Errorf("%s: twin %q (%v), signer %q (%v), corpus %q", row.Name, got, err, want, wantErr, row.SignatureHex)
		}
	}
	for _, row := range load[requestRow](t, "request-acceptance-vectors.json").Vectors {
		priv, _ := keyOf(t, row.SeedHex)
		want, wantErr := helpers.SignRequestAcceptance(priv, row.request())
		got, err := helperstest.SignRequestAcceptanceAnyRequester(priv, row.request())
		if wantErr != nil || err != nil || !proto.Equal(got, want) || got.GetSignature() != row.SignatureHex {
			t.Errorf("%s: twin %v (%v), signer %v (%v)", row.Name, got, err, want, wantErr)
		}
	}
}

// Every refusal but the requester's is the signer's own, in text and in order.
func TestEveryOtherRefusalIsKept(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	named := &forav1.Requester{Id: "agent-1", Domain: "agent.example"}
	noID := &forav1.Requester{Domain: "agent.example"}
	signed := &forav1.Offer{Signature: "sig", Exchange: "one.example"}
	unsigned := &forav1.Offer{Exchange: "one.example"}
	item := func(o *forav1.Offer) *forav1.TransactionItem { return &forav1.TransactionItem{Offer: o} }
	req := func(r *forav1.Requester, items ...*forav1.TransactionItem) *forav1.TransactionRequest {
		return &forav1.TransactionRequest{Requester: r, IdempotencyKey: "idem", Items: items}
	}
	payload := func(items ...*forav1.AgentRequestAcceptanceItem) *forav1.AgentRequestAcceptancePayload {
		return &forav1.AgentRequestAcceptancePayload{Items: items, RequesterId: "agent-1", RequesterDomain: "agent.example"}
	}
	tooMany := make([]*forav1.AgentRequestAcceptanceItem, 257)
	for i := range tooMany {
		tooMany[i] = &forav1.AgentRequestAcceptanceItem{OfferSig: "sig", Exchange: "one.example"}
	}

	offerBytes := func(o *forav1.Offer, r *forav1.Requester) (func() error, func() error) {
		return func() error { _, err := helpers.CanonicalAcceptanceBytes(o, r, "idem"); return err },
			func() error { _, err := helperstest.CanonicalAcceptanceBytesAnyRequester(o, r, "idem"); return err }
	}
	offerSign := func(k ed25519.PrivateKey, o *forav1.Offer, r *forav1.Requester) (func() error, func() error) {
		return func() error { _, err := helpers.SignOfferAcceptance(k, o, r, "idem"); return err },
			func() error { _, err := helperstest.SignOfferAcceptanceAnyRequester(k, o, r, "idem"); return err }
	}
	requestBytes := func(p *forav1.AgentRequestAcceptancePayload) (func() error, func() error) {
		return func() error { _, err := helpers.CanonicalRequestAcceptanceBytes(p); return err },
			func() error { _, err := helperstest.CanonicalRequestAcceptanceBytesAnyRequester(p); return err }
	}
	requestSign := func(k ed25519.PrivateKey, q *forav1.TransactionRequest) (func() error, func() error) {
		return func() error { _, err := helpers.SignRequestAcceptance(k, q); return err },
			func() error { _, err := helperstest.SignRequestAcceptanceAnyRequester(k, q); return err }
	}
	cases := []struct {
		name    string
		calls   func() (func() error, func() error)
		wantErr string // set when the twin must differ: the next fault after the requester's
	}{
		{"nil offer", func() (func() error, func() error) { return offerBytes(nil, named) }, ""},
		{"nil requester", func() (func() error, func() error) { return offerBytes(signed, nil) }, ""},
		{"unsigned offer", func() (func() error, func() error) { return offerBytes(unsigned, named) }, ""},
		{"unsigned offer and no requester id", func() (func() error, func() error) { return offerBytes(unsigned, noID) }, ""},
		{"short key", func() (func() error, func() error) { return offerSign(priv[:3], signed, named) }, ""},
		{"nil payload", func() (func() error, func() error) { return requestBytes(nil) }, ""},
		{"no items", func() (func() error, func() error) { return requestBytes(payload()) }, ""},
		{"too many items", func() (func() error, func() error) { return requestBytes(payload(tooMany...)) }, ""},
		{
			"an item with no signature", func() (func() error, func() error) {
				return requestBytes(payload(&forav1.AgentRequestAcceptanceItem{Exchange: "one.example"}))
			}, "",
		},
		{
			"an item naming no exchange", func() (func() error, func() error) {
				return requestBytes(payload(&forav1.AgentRequestAcceptanceItem{OfferSig: "sig"}))
			}, "",
		},
		{"request: short key", func() (func() error, func() error) { return requestSign(priv[:3], req(named, item(signed))) }, ""},
		{"request: nil request", func() (func() error, func() error) { return requestSign(priv, nil) }, ""},
		{"request: no items", func() (func() error, func() error) { return requestSign(priv, req(named)) }, ""},
		{"request: an unsigned item", func() (func() error, func() error) { return requestSign(priv, req(named, item(unsigned))) }, ""},
		{
			"request: no requester id and no items",
			func() (func() error, func() error) { return requestSign(priv, req(noID)) },
			"helpers: transaction request has no items",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signer, twin := c.calls()
			signerErr, twinErr := signer(), twin()
			if signerErr == nil || twinErr == nil {
				t.Fatalf("signer %v, twin %v; both must refuse", signerErr, twinErr)
			}
			want := signerErr.Error()
			if c.wantErr != "" {
				want = c.wantErr
			}
			if twinErr.Error() != want {
				t.Errorf("twin = %q, want %q", twinErr.Error(), want)
			}
		})
	}
}

// Production code never imports this package: what it signs, a conforming party must
// never send.
func TestNothingButTestsImportThisPackage(t *testing.T) {
	const self = "github.com/FORA-Protocol/protocol/sdk/go/helperstest"
	root := filepath.Join("..", "..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "node_modules" || name == ".git" || strings.HasPrefix(name, ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				t.Errorf("%s imports %s", path, self)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
