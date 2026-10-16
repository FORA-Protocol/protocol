package helpers_test

// A request carrying several signatures, under the Web Bot Auth profile. Every
// signature is verified on its own, against the key its keyid names in the
// directory its OWN covered Signature-Agent member names. A signature need not
// cover another (WG-00 §5.2.2: a forwarder MAY); one that does must cover the
// earlier signature's Signature member, its Signature-Input member and every
// component it lists, and may only cover a signature that appears before it. The
// hop budget counts every signature. Labels carry no meaning: sig1..sigN is the
// SDK's convention, not a rule.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// directoryResolver resolves a keyid only in the directory it was registered
// under, so a signature resolved through the wrong member fails.
type directoryResolver map[string]ed25519.PublicKey

func (d directoryResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	dir := helpers.SignatureAgentFromContext(ctx)
	if pub, ok := d[dir+" "+keyID]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: %s in %s", helpers.ErrUnknownKey, keyID, dir)
}

type hop struct {
	signer helpers.Signer
	pub    ed25519.PublicKey
	origin string
}

func newHop(t *testing.T, keyID, origin string) hop {
	t.Helper()
	signer, pub := mustSigner(t, keyID)
	return hop{signer: signer, pub: pub, origin: origin}
}

func resolverFor(hops ...hop) directoryResolver {
	r := directoryResolver{}
	for _, h := range hops {
		r[h.origin+" "+h.signer.KeyID()] = h.pub
	}
	return r
}

// signHops signs req with the first hop through SignRequest and every later hop
// through AppendSignature, each with cover set as the CoverPrevious option.
func signHops(t *testing.T, req *http.Request, body []byte, cover bool, hops ...hop) {
	t.Helper()
	for i, h := range hops {
		opts := helpers.SignOptions{Created: tCreated, Expires: tExpires, SignatureAgent: h.origin, CoverPrevious: cover}
		var err error
		if i == 0 {
			err = helpers.SignRequest(context.Background(), req, body, h.signer, opts)
		} else {
			err = helpers.AppendSignature(context.Background(), req, body, h.signer, opts)
		}
		if err != nil {
			t.Fatalf("hop %d: %v", i, err)
		}
	}
}

func verifyAll(t *testing.T, req *http.Request, body []byte, r helpers.KeyResolver, max int) ([]helpers.VerifiedRequest, error) {
	t.Helper()
	return helpers.VerifyMultisigRequestResolved(context.Background(), req, body, r,
		helpers.VerifyOptions{Now: tNow, MaxSignatures: max})
}

// TestMultisig_independentSignaturesEachResolveInTheirOwnDirectory: two
// signatures that do not cover each other both verify, each resolved through its
// own member, and the result carries each signer's directory.
func TestMultisig_independentSignaturesEachResolveInTheirOwnDirectory(t *testing.T) {
	agent, broker := newHop(t, "agent.v1", tAgent), newHop(t, "broker.v1", tBroker)
	req, body := profileRequest(t, []byte(`{"q":1}`), ""), []byte(`{"q":1}`)
	signHops(t, req, body, false, agent, broker)

	if got := req.Header.Get(helpers.SignatureAgentHeader); got != `sig1="`+tAgent+`", sig2="`+tBroker+`"` {
		t.Errorf("Signature-Agent = %q", got)
	}
	if strings.Contains(req.Header.Get("Signature-Input"), `"signature";key=`) {
		t.Errorf("an append without CoverPrevious covered an earlier signature: %s", req.Header.Get("Signature-Input"))
	}
	verified, err := verifyAll(t, req, body, resolverFor(agent, broker), 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verified) != 2 || verified[0].SignatureAgent != tAgent || verified[1].SignatureAgent != tBroker {
		t.Fatalf("verified = %+v", verified)
	}
}

// TestMultisig_aSignatureIsNotResolvedThroughAnotherMember: the broker's key is
// published only in the broker's directory. A broker signature that covers the
// AGENT's member is resolved in the agent's directory, does not find the key there,
// and the request is refused.
func TestMultisig_aSignatureIsNotResolvedThroughAnotherMember(t *testing.T) {
	agent, broker := newHop(t, "agent.v1", tAgent), newHop(t, "broker.v1", tBroker)
	body := []byte(`{"q":1}`)
	req := profileRequest(t, body, "")
	signHops(t, req, body, false, agent)
	req.Header.Set(helpers.SignatureAgentHeader, req.Header.Get(helpers.SignatureAgentHeader)+`, sig2="`+tBroker+`"`)
	raw := helpers.RawSignature{
		Label: "sig2", Covered: append(plainCovered(foraRPC...), memberCovered("sig1")),
		Created: tCreated, Expires: tExpires, Tag: helpers.WBATag,
	}
	if err := helpers.SignRawForTest(req, broker.signer, raw, true); err != nil {
		t.Fatal(err)
	}
	_, err := verifyAll(t, req, body, resolverFor(agent, broker), 0)
	if !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("verify error = %v, want ErrUnknownKey from resolving in the agent's directory", err)
	}
}

// TestMultisig_coverPreviousCoversTheEarlierSignatureCompletely: under
// CoverPrevious the new signature covers the earlier one's Signature member, its
// Signature-Input member and every component it lists, and a three-signature
// chain verifies.
func TestMultisig_coverPreviousCoversTheEarlierSignatureCompletely(t *testing.T) {
	a, b, c := newHop(t, "a.v1", "https://a.example"), newHop(t, "b.v1", "https://b.example"), newHop(t, "c.v1", "https://c.example")
	body := []byte(`{"q":2}`)
	req := profileRequest(t, body, "")
	signHops(t, req, body, true, a, b, c)

	members := strings.Split(req.Header.Get("Signature-Input"), ", sig")
	if len(members) != 3 {
		t.Fatalf("Signature-Input = %s", req.Header.Get("Signature-Input"))
	}
	sig2 := members[1]
	for _, want := range []string{`"signature-agent";key="sig1"`, `"signature";key="sig1"`, `"signature-input";key="sig1"`, `"signature-agent";key="sig2"`} {
		if !strings.Contains(sig2, want) {
			t.Errorf("sig2 does not cover %s: %s", want, sig2)
		}
	}
	verified, err := verifyAll(t, req, body, resolverFor(a, b, c), 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verified) != 3 {
		t.Fatalf("verified %d signatures, want 3", len(verified))
	}
	// Tampering with sig1 now breaks sig1 itself and every signature covering it.
	req.Header.Set("Signature", corruptFirstMember(req.Header.Get("Signature")))
	if _, err := verifyAll(t, req, body, resolverFor(a, b, c), 0); !errors.Is(err, helpers.ErrSignatureVerify) {
		t.Fatalf("tampered sig1: %v, want ErrSignatureVerify", err)
	}
}

// TestMultisig_incompleteCoverageIsRefused: each way a signature can cover an
// earlier one partially, or name one that is not earlier, is refused before any
// crypto as ErrBrokenSignatureChain.
func TestMultisig_incompleteCoverageIsRefused(t *testing.T) {
	agent, broker := newHop(t, "agent.v1", tAgent), newHop(t, "broker.v1", tBroker)
	link := func(name, key string) helpers.CoveredComponent {
		return helpers.CoveredComponent{Name: name, Params: []helpers.ComponentParam{{Key: "key", Val: key}}}
	}
	own := append(plainCovered(foraRPC...), memberCovered("sig2"))
	for _, tc := range []struct {
		name    string
		covered []helpers.CoveredComponent
	}{
		{"signature without signature-input", append(append([]helpers.CoveredComponent{}, own...), memberCovered("sig1"), link("signature", "sig1"))},
		{"without a component sig1 lists", append(append([]helpers.CoveredComponent{}, own...), link("signature", "sig1"), link("signature-input", "sig1"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"q":3}`)
			req := profileRequest(t, body, "")
			signHops(t, req, body, false, agent)
			req.Header.Set(helpers.SignatureAgentHeader, req.Header.Get(helpers.SignatureAgentHeader)+`, sig2="`+tBroker+`"`)
			raw := helpers.RawSignature{Label: "sig2", Covered: tc.covered, Created: tCreated, Expires: tExpires, Tag: helpers.WBATag}
			if err := helpers.SignRawForTest(req, broker.signer, raw, true); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyAll(t, req, body, resolverFor(agent, broker), 0); !errors.Is(err, helpers.ErrBrokenSignatureChain) {
				t.Fatalf("verify error = %v, want ErrBrokenSignatureChain", err)
			}
		})
	}
}

// TestMultisig_coverageMustNameAnEarlierSignature: a coverage naming a label that
// is not on the request, or the covering signature itself, is refused as
// ErrBrokenSignatureChain before any signature is checked, so the edit to
// Signature-Input that produces it is reported as the coverage it breaks.
func TestMultisig_coverageMustNameAnEarlierSignature(t *testing.T) {
	agent, broker := newHop(t, "agent.v1", tAgent), newHop(t, "broker.v1", tBroker)
	for _, tc := range []struct{ name, to string }{{"a label not on the request", "sig9"}, {"itself", "sig2"}} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"q":8}`)
			req := profileRequest(t, body, "")
			signHops(t, req, body, true, agent, broker)
			in := req.Header.Get("Signature-Input")
			cut := strings.Index(in, ", sig2=")
			req.Header.Set("Signature-Input", in[:cut]+strings.ReplaceAll(in[cut:], `"signature-input";key="sig1"`, `"signature-input";key="`+tc.to+`"`))
			if _, err := verifyAll(t, req, body, resolverFor(agent, broker), 0); !errors.Is(err, helpers.ErrBrokenSignatureChain) {
				t.Fatalf("verify error = %v, want ErrBrokenSignatureChain", err)
			}
		})
	}
}

// TestMultisig_coverageMustPointBackwards: swapping the order of a covering pair
// puts the covered signature after the one covering it, which is refused.
func TestMultisig_coverageMustPointBackwards(t *testing.T) {
	agent, broker := newHop(t, "agent.v1", tAgent), newHop(t, "broker.v1", tBroker)
	body := []byte(`{"q":4}`)
	req := profileRequest(t, body, "")
	signHops(t, req, body, true, agent, broker)
	for _, h := range []string{"Signature-Input", "Signature"} {
		parts := strings.SplitN(req.Header.Get(h), ", ", 2)
		req.Header.Set(h, parts[1]+", "+parts[0])
	}
	if _, err := verifyAll(t, req, body, resolverFor(agent, broker), 0); !errors.Is(err, helpers.ErrBrokenSignatureChain) {
		t.Fatalf("verify error = %v, want ErrBrokenSignatureChain", err)
	}
}

// TestMultisig_hopBudgetCountsEverySignature: three independent signatures exceed
// a budget of two whether or not any covers another.
func TestMultisig_hopBudgetCountsEverySignature(t *testing.T) {
	for _, cover := range []bool{false, true} {
		t.Run(fmt.Sprintf("cover=%v", cover), func(t *testing.T) {
			a, b, c := newHop(t, "a.v1", "https://a.example"), newHop(t, "b.v1", "https://b.example"), newHop(t, "c.v1", "https://c.example")
			body := []byte(`{"q":5}`)
			req := profileRequest(t, body, "")
			signHops(t, req, body, cover, a, b, c)
			if _, err := verifyAll(t, req, body, resolverFor(a, b, c), 2); !errors.Is(err, helpers.ErrTooManyHops) {
				t.Fatalf("verify error = %v, want ErrTooManyHops", err)
			}
			if _, err := verifyAll(t, req, body, resolverFor(a, b, c), 3); err != nil {
				t.Fatalf("within budget: %v", err)
			}
		})
	}
}

// TestMultisig_legacyFormOnlyOnASingleSignature: the legacy String form names one
// directory and cannot take a second member. A verifier refuses it on a request
// carrying two signatures, and a forwarder refuses to append to it.
func TestMultisig_legacyFormOnlyOnASingleSignature(t *testing.T) {
	agent, broker := newHop(t, "agent.v1", tAgent), newHop(t, "broker.v1", tBroker)
	body := []byte(`{"q":6}`)
	req := profileRequest(t, body, `"`+tAgent+`"`)
	rawSign(t, req, agent.signer, func(r *helpers.RawSignature) {
		r.Covered = plainCovered(append(foraRPC, "signature-agent")...)
	})
	err := helpers.AppendSignature(context.Background(), req, body, broker.signer,
		helpers.SignOptions{Created: tCreated, Expires: tExpires, SignatureAgent: tBroker})
	if !errors.Is(err, helpers.ErrSignatureAgentForm) {
		t.Fatalf("appending to the legacy form: %v, want ErrSignatureAgentForm", err)
	}
	// A second signature carried beside it anyway is refused at the verifier.
	raw := helpers.RawSignature{
		Label: "sig2", Covered: plainCovered(append(foraRPC, "signature-agent")...),
		Created: tCreated, Expires: tExpires, Tag: helpers.WBATag,
	}
	if err := helpers.SignRawForTest(req, broker.signer, raw, true); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAll(t, req, body, resolverFor(agent, broker), 0); !errors.Is(err, helpers.ErrSignatureAgentForm) {
		t.Fatalf("verify error = %v, want ErrSignatureAgentForm", err)
	}
}

// TestAppendSignature_labelsAvoidEveryUsedName: the appended label is the first
// sigN no signature and no Signature-Agent member uses, and a caller's label that
// collides is refused.
func TestAppendSignature_labelsAvoidEveryUsedName(t *testing.T) {
	agent, broker := newHop(t, "agent.v1", tAgent), newHop(t, "broker.v1", tBroker)
	body := []byte(`{"q":7}`)
	req := profileRequest(t, body, `sig2="https://other.example"`)
	rawSign(t, req, agent.signer, func(r *helpers.RawSignature) {
		r.Covered = append(plainCovered(foraRPC...), memberCovered("sig2"))
	})
	opts := helpers.SignOptions{Created: tCreated, Expires: tExpires, SignatureAgent: tBroker}
	if err := helpers.AppendSignature(context.Background(), req, body, broker.signer, opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.Header.Get("Signature-Input"), ", sig3=") {
		t.Errorf("appended label is not sig3: %s", req.Header.Get("Signature-Input"))
	}
	opts.Label = "sig1"
	if err := helpers.AppendSignature(context.Background(), req, body, broker.signer, opts); !errors.Is(err, helpers.ErrSignatureLabel) {
		t.Errorf("a colliding label: %v, want ErrSignatureLabel", err)
	}
}

// corruptFirstMember flips a character in the first dictionary member's base64
// payload of a Signature header value.
func corruptFirstMember(sig string) string {
	b := []byte(sig)
	for i := 0; i < len(b); i++ {
		if b[i] == ':' && i+1 < len(b) {
			if b[i+1] == 'A' {
				b[i+1] = 'B'
			} else {
				b[i+1] = 'A'
			}
			break
		}
	}
	return string(b)
}
