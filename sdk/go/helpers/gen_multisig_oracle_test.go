package helpers

// The oracle of the multi-signature corpus: the REAL VerifyMultisigRequestResolved
// over a request rebuilt from a vector's columns, with a resolver that finds a key
// only under the directory it was registered with. The emitter takes every
// expectation from it, and the self-consistency guard re-runs it over each emitted
// vector.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// pairResolver resolves a keyid only under the directory it was registered with.
type pairResolver map[string]ed25519.PublicKey

func (p pairResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	dir := SignatureAgentFromContext(ctx)
	if pub, ok := p[dir+" "+keyID]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: keyid=%q directory=%q", ErrUnknownKey, keyID, dir)
}

// multisigOracleOutcome drives the REAL VerifyMultisigRequestResolved over the
// reconstructed request with a (directory, keyid) resolver and the vector's hop
// budget, returning the verified keyids and directories on success, or the
// classified reject reason and the Accept-Signature value the refusal carries.
func multisigOracleOutcome(t *testing.T, v multisigChainVector) (keyids, dirs []string, reason, accept string) {
	t.Helper()
	body, err := hex.DecodeString(v.BodyHex)
	if err != nil {
		t.Fatalf("%s: decode body: %v", v.Name, err)
	}
	req, err := http.NewRequestWithContext(context.Background(), v.Method, v.URL, nil)
	if err != nil {
		t.Fatalf("%s: new request: %v", v.Name, err)
	}
	req.Header.Set("Content-Digest", v.ContentDigest)
	req.Header.Set("Authorization", v.Authorization)
	req.Header.Set(SignatureAgentHeader, v.SignatureAgent)
	req.Header.Set("Signature-Input", v.SignatureInput)
	req.Header.Set("Signature", v.Signature)
	for _, name := range v.OmitHeaders {
		req.Header.Del(name)
	}
	// Add, not Set: an extra line lands BESIDE the base one under the same covered
	// name. Sorted so the emitted vector is deterministic — map iteration is not.
	for _, name := range slices.Sorted(maps.Keys(v.ExtraHeaders)) {
		req.Header.Add(name, v.ExtraHeaders[name])
	}
	resolver := pairResolver{}
	for _, h := range v.Hops {
		raw, derr := base64.RawURLEncoding.DecodeString(h.PubkeyB64URL)
		if derr != nil {
			t.Fatalf("%s: decode hop pub: %v", v.Name, derr)
		}
		resolver[h.Directory+" "+h.KeyID] = ed25519.PublicKey(raw)
	}
	opts := VerifyOptions{Now: time.Unix(msNow, 0), MaxSignatures: v.MaxSignatures}
	verified, verr := VerifyMultisigRequestResolved(context.Background(), req, body, resolver, opts)
	if verr != nil {
		accept, _ = AcceptSignatureFor(verr)
		return nil, nil, classifyNegReason(verr), accept
	}
	for i := range verified {
		keyids = append(keyids, verified[i].KeyID)
		dirs = append(dirs, verified[i].SignatureAgent)
	}
	return keyids, dirs, "", ""
}

// verifyMultisigChainVector is the self-consistency guard: it re-runs the oracle
// over the emitted vector and asserts the recorded outcome matches.
func verifyMultisigChainVector(t *testing.T, v multisigChainVector) {
	t.Helper()
	keyids, dirs, reason, accept := multisigOracleOutcome(t, v)
	if reason != v.ExpectedReason || (reason == "") != v.ExpectedVerified || accept != v.ExpectedAcceptSignature ||
		strings.Join(keyids, ",") != strings.Join(v.ExpectedKeyIDs, ",") ||
		strings.Join(dirs, ",") != strings.Join(v.ExpectedDirectories, ",") {
		t.Fatalf("chain vector %s: oracle (%q, %v, %v), recorded (%q, %v, %v)", v.Name,
			reason, keyids, dirs, v.ExpectedReason, v.ExpectedKeyIDs, v.ExpectedDirectories)
	}
}
