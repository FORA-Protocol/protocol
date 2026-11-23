package helpers_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// popHeaders writes a vector's request headers: the presented key and, when the
// vector carries them, the three signature headers.
func popHeaders(v popVector) http.Header {
	h := http.Header{}
	h.Set(helpers.AgentKeyHeader, v.PresentedKeyB64URL)
	for name, value := range map[string]string{
		helpers.SignatureAgentHeader: v.SignatureAgent, "Signature-Input": v.SignatureInput, "Signature": v.Signature,
	} {
		if value != "" {
			h.Set(name, value)
		}
	}
	return h
}

// TestVerifyAgentBinding_ReplaysSharedVectors replays every pop vector through the
// verify face and requires the recorded verdict, reason and Accept-Signature.
func TestVerifyAgentBinding_ReplaysSharedVectors(t *testing.T) {
	for _, v := range loadPopVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			got, err := helpers.VerifyAgentBinding(v.Method, v.URL, popHeaders(v), v.AgentID,
				helpers.PoPVerifyOptions{Now: time.Unix(v.NowUnix, 0)})
			if v.ExpectedValid {
				if err != nil {
					t.Fatalf("refused a proof the vector accepts: %v", err)
				}
				if got.SignatureAgent != "https://agent.example" || got.KeyID != v.AgentID ||
					got.KeyDirectory != v.ExpectedKeyDirectory {
					t.Errorf("verified = %+v, want key directory %q", got, v.ExpectedKeyDirectory)
				}
				return
			}
			var perr *helpers.PoPError
			if !errors.As(err, &perr) {
				t.Fatalf("err = %v, want a PoPError", err)
			}
			if string(perr.Reason) != v.ExpectedReason || perr.AcceptSignature != v.ExpectedAcceptSignature {
				t.Errorf("refusal = (%q, %q), want (%q, %q)", perr.Reason, perr.AcceptSignature,
					v.ExpectedReason, v.ExpectedAcceptSignature)
			}
		})
	}
}

// TestVerifyAgentBinding_namesTheMemberRuleThatRefused: every WG-01 member
// refusal in pop-vectors.json is bad_signature_agent with Accept-Signature on the
// wire, which the shared replay checks. What a row cannot express is which member
// rule refused it, so a Go caller can tell an ignored member from a URL that is
// not the key directory: each row's error wraps exactly its rule's sentinel.
func TestVerifyAgentBinding_namesTheMemberRuleThatRefused(t *testing.T) {
	rules := map[string]error{
		"member_with_parameter":      helpers.ErrSignatureAgentIgnored,
		"member_other_path":          helpers.ErrSignatureAgentNotKeyDirectory,
		"member_query":               helpers.ErrSignatureAgentNotKeyDirectory,
		"member_fragment":            helpers.ErrSignatureAgentNotKeyDirectory,
		"member_http_well_known_url": helpers.ErrSignatureAgentNotOrigin,
		"member_not_https_origin":    helpers.ErrSignatureAgentNotOrigin,
	}
	seen := 0
	for _, v := range loadPopVectors(t) {
		want, ok := rules[v.Name]
		if !ok {
			continue
		}
		seen++
		t.Run(v.Name, func(t *testing.T) {
			_, err := helpers.VerifyAgentBinding(v.Method, v.URL, popHeaders(v), v.AgentID,
				helpers.PoPVerifyOptions{Now: time.Unix(v.NowUnix, 0)})
			if !errors.Is(err, want) {
				t.Fatalf("err = %v, want %v", err, want)
			}
			for _, other := range rules {
				if !errors.Is(want, other) && errors.Is(err, other) {
					t.Errorf("err = %v also matches %v", err, other)
				}
			}
		})
	}
	if seen != len(rules) {
		t.Fatalf("pop-vectors.json carries %d of the %d member-rule rows", seen, len(rules))
	}
}

// TestVerifyAgentBinding_RoundTripsTheSignerAndBindsTheURL signs a proof for a
// percent-encoded URL with any method, verifies it, and refuses it against another
// URL, another method and another agent.
func TestVerifyAgentBinding_RoundTripsTheSignerAndBindsTheURL(t *testing.T) {
	v := validPopVector(t)
	signer, pub := signerFor(t, v.SignerSeedHex, v.AgentID)
	url := "https://cdn.example/a%2Fb/doc?agent_id=" + v.AgentID
	created := time.Now().Unix()
	b, err := helpers.SignAgentBinding(context.Background(), signer, pub, helpers.PoPOptions{
		URL: url, Created: created, Expires: created + 60, Method: http.MethodHead,
		SignatureAgent: "https://agent.example", Nonce: v.Nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	b.Apply(h)
	if _, err := helpers.VerifyAgentBinding(
		http.MethodHead,
		url,
		h,
		v.AgentID,
		helpers.PoPVerifyOptions{},
	); err != nil {
		t.Fatalf("the signer's own proof: %v", err)
	}
	for name, tc := range map[string]struct{ method, url, agent string }{
		"another URL":    {http.MethodHead, url + "&x=1", v.AgentID},
		"another method": {http.MethodGet, url, v.AgentID},
		"another agent":  {http.MethodHead, url, "someone-else"},
	} {
		if _, err := helpers.VerifyAgentBinding(
			tc.method,
			tc.url,
			h,
			tc.agent,
			helpers.PoPVerifyOptions{},
		); err == nil {
			t.Errorf("%s: a proof verified that should not", name)
		}
	}
}
