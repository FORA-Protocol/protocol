package helpers

// Multi-signature golden-vector emitter (ADR-020 §8).
//
// The sdk/ts and sdk/python multi-signature faces assert byte-parity against this
// Go oracle: a request signed by SignRequest (sig1) and AppendSignature (sig2,
// sig3, with or without CoverPrevious) must reconstruct byte-for-byte in TS and
// Python, and every rejection must match the Go taxonomy token-for-token. Rather
// than hand-author the wire bytes, this emitter signs with the REAL Go signer and
// appender (and, for the forms they refuse, signs by hand over the same base
// builder), and DERIVES every expected outcome from the REAL
// VerifyMultisigRequestResolved.
//
// Every hop names its own key directory, and the oracle's resolver finds a key
// only under the directory it was registered with — the (directory, keyid) pair.
// A port that resolves a signature through any member but the one that signature
// covers fails the vectors.
//
// Determinism: every hop key is derived from a FIXED fixedSeed byte and the
// created/expires window is pinned, so a re-emit is byte-identical (drift-gated).

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Shared request material for every multi-signature vector — one target, one
// body, one window — so the vectors differ only in their signatures and mutation.
const (
	msMethod  = http.MethodPost
	msURL     = "https://exchange.example.com/fora.v1.ExchangeService/ExecuteTransaction"
	msAuth    = "Bearer chain-token"
	msCreated = int64(1_700_000_000)
	msExpires = int64(1_700_000_300)
	msNow     = int64(1_700_000_100) // inside the window
)

// multisigHop records one signer so a TS/Python port can re-derive the exact
// request: it re-signs each hop under its seed and directory and byte-matches the
// emitted headers. pubkey and directory are what the port registers in its
// resolver, under the (directory, keyid) pair.
type multisigHop struct {
	KeyID        string `json:"keyid"`
	PubkeyB64URL string `json:"pubkey_b64url"`
	SeedHex      string `json:"seed_hex"`
	// Directory is the https origin the hop signs as: its Signature-Agent member.
	Directory string `json:"directory"`
	// Nonce is the RFC 9421 nonce this hop signed with; absent for none.
	Nonce string `json:"nonce,omitempty"`
	// CoverPrevious marks a hop appended with SignOptions.CoverPrevious.
	CoverPrevious bool `json:"cover_previous,omitempty"`
}

// multisigChainVector is one multi-signature case: the full wire request (every
// label in Signature-Input, Signature and Signature-Agent), the signers, and the
// outcome the REAL Go oracle reaches — the verified keyids and directories in
// header order for a positive, or the reject reason token for a negative
// (hop_budget / broken_chain / signature).
type multisigChainVector struct {
	Name          string `json:"name"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	BodyHex       string `json:"body_hex"`
	Authorization string `json:"authorization"`
	// SignatureAgent is the Signature-Agent header value the request carries.
	SignatureAgent string        `json:"signature_agent"`
	Created        int64         `json:"created"`
	Expires        int64         `json:"expires"`
	ContentDigest  string        `json:"content_digest"`
	SignatureInput string        `json:"signature_input"`
	Signature      string        `json:"signature"`
	Hops           []multisigHop `json:"hops"`
	// MaxSignatures is the hop budget the verifier is pinned to (0 = unbounded).
	MaxSignatures int `json:"max_signatures"`
	// ExpectedVerified is the verdict; ExpectedKeyIDs and ExpectedDirectories are
	// the verified signatures' keyids and directories in header order (present
	// only when verified); ExpectedReason is the RejectReason token for a
	// negative ("" for a positive).
	ExpectedVerified    bool     `json:"expected_verified"`
	ExpectedKeyIDs      []string `json:"expected_keyids"`
	ExpectedDirectories []string `json:"expected_directories"`
	ExpectedReason      string   `json:"expected_reason"`
	// OmitHeaders names the header fields the request does NOT carry, deleted
	// after the base ones are set. ABSENT is not EMPTY: the base is rebuilt from
	// the request that arrived, so a covered name with no field line cannot be
	// reconstructed. It also pins the REJECT PRECEDENCE: the missing header is
	// found while a signature's base is rebuilt, after the hop budget and the
	// coverage check, so a request that is over budget or covers incompletely
	// keeps ITS reason.
	OmitHeaders []string `json:"omit_headers,omitempty"`
	// ExtraHeaders are field lines ADDED after the base ones, joined with the
	// base line under the same name rather than overriding it.
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// hopSpec names a signer: its seed byte, its directory, its nonce and whether it
// covers the signature before it.
type hopSpec struct {
	seedByte  byte
	directory string
	nonce     string
	cover     bool
}

func (h hopSpec) keyID(t *testing.T) string { return seedThumbprint(t, fixedSeed(h.seedByte)) }

func (h hopSpec) record(t *testing.T) multisigHop {
	seed := fixedSeed(h.seedByte)
	return multisigHop{
		KeyID: h.keyID(t), PubkeyB64URL: b64urlNoPad(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)),
		SeedHex: hex.EncodeToString(seed), Directory: h.directory, Nonce: h.nonce, CoverPrevious: h.cover,
	}
}

// msRequest is a fresh request carrying the given Authorization field lines.
func msRequest(t *testing.T, authorizationLines []string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(msMethod, msURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Add, not Set: each entry is its own field line under the one covered name.
	for _, line := range authorizationLines {
		req.Header.Add("Authorization", line)
	}
	return req
}

// signHopsOn signs req with each hop: hop[0] via the REAL SignRequest and each
// later hop via the REAL AppendSignature, with its CoverPrevious option.
func signHopsOn(t *testing.T, req *http.Request, body []byte, hops []hopSpec) []multisigHop {
	t.Helper()
	out := make([]multisigHop, 0, len(hops))
	for i, h := range hops {
		signer, err := NewEd25519SignerFromSeed(h.keyID(t), fixedSeed(h.seedByte))
		if err != nil {
			t.Fatalf("hop %d signer: %v", i, err)
		}
		opts := SignOptions{
			Created: msCreated, Expires: msExpires, Nonce: h.nonce, SignatureAgent: h.directory, CoverPrevious: h.cover,
		}
		sign := AppendSignature
		if i == 0 {
			sign = SignRequest
		}
		if err := sign(context.Background(), req, body, signer, opts); err != nil {
			t.Fatalf("hop %d: %v", i, err)
		}
		out = append(out, h.record(t))
	}
	return out
}

// signHopByHand appends a signature labelled label made by h over exactly
// covered, adding memberHeader (when non-empty) to Signature-Agent first. It
// builds the signatures the appender refuses to make.
func signHopByHand(t *testing.T, req *http.Request, h hopSpec, label string, covered []CoveredComponent, memberHeader string) multisigHop {
	t.Helper()
	signer, err := NewEd25519SignerFromSeed(h.keyID(t), fixedSeed(h.seedByte))
	if err != nil {
		t.Fatal(err)
	}
	if memberHeader != "" {
		existing := joinedHeader(req.Header, SignatureAgentHeader)
		if existing != "" {
			memberHeader = existing + ", " + memberHeader
		}
		req.Header.Set(SignatureAgentHeader, memberHeader)
	}
	p := sigParams{
		Label: label, Covered: covered, KeyID: h.keyID(t), Alg: AlgEd25519,
		Created: msCreated, Expires: msExpires, Nonce: h.nonce, Tag: WBATag,
	}
	if err := signWithParams(context.Background(), req, p, signer, sigWriteAppend); err != nil {
		t.Fatalf("sign %s by hand: %v", label, err)
	}
	return h.record(t)
}

// mkMultisigVector templates a vector from a signed request's wire bytes.
func mkMultisigVector(name string, req *http.Request, hops []multisigHop, body []byte, maxSig int) multisigChainVector {
	return multisigChainVector{
		Name: name, Method: msMethod, URL: msURL, BodyHex: hex.EncodeToString(body),
		Authorization:  req.Header.Values("Authorization")[0],
		SignatureAgent: req.Header.Get(SignatureAgentHeader),
		Created:        msCreated, Expires: msExpires,
		ContentDigest:  req.Header.Get("Content-Digest"),
		SignatureInput: req.Header.Get("Signature-Input"),
		Signature:      req.Header.Get("Signature"),
		Hops:           hops, MaxSignatures: maxSig,
	}
}

// buildMultisigChainVectors emits the multi-signature corpus. Every outcome is
// DERIVED from the REAL VerifyMultisigRequestResolved via multisigOracleOutcome —
// never hand-authored.
func buildMultisigChainVectors(t *testing.T) []multisigChainVector {
	t.Helper()
	body := []byte(`{"idempotency_key":"idem-1"}`)
	agent := hopSpec{seedByte: 0x90, directory: "https://agent.example"}
	broker := hopSpec{seedByte: 0x91, directory: "https://broker.example"}
	relay := hopSpec{seedByte: 0x92, directory: "https://relay.example:8443"}
	covering := func(h hopSpec) hopSpec { h.cover = true; return h }
	signed := func(name string, maxSig int, hops ...hopSpec) multisigChainVector {
		req := msRequest(t, []string{msAuth})
		recs := signHopsOn(t, req, body, hops)
		return mkMultisigVector(name, req, recs, body, maxSig)
	}

	var out []multisigChainVector
	// Two signatures that do not cover each other, each resolved in its own
	// directory: the shape FORA's own legs never produce but WG-00 permits.
	out = append(out, signed("positive_independent_two", 0, agent, broker))
	// A forwarder covering the signature before it, completely.
	out = append(out, signed("positive_covering_two", 0, agent, covering(broker)))
	out = append(out, signed("positive_covering_three", 0, agent, covering(broker), covering(relay)))
	// The same with the 64-byte nonces the transports emit.
	agentN, brokerN := agent, covering(broker)
	agentN.nonce, brokerN.nonce = nonce64A, nonce64B
	out = append(out, signed("positive_covering_two_nonce", 0, agentN, brokerN))

	// Three valid signatures under a budget of two: refused before any crypto,
	// whether or not they cover each other.
	out = append(out, signed("hop_budget_three_independent_over_two", 2, agent, broker, relay))
	out = append(out, signed("hop_budget_three_covering_over_two", 2, agent, covering(broker), covering(relay)))

	// A covering pair with its order swapped: sig2 now covers a signature that
	// appears after it.
	reordered := signed("broken_coverage_reordered", 0, agent, covering(broker))
	reordered.SignatureInput = msSwapTwoMembers(reordered.SignatureInput)
	reordered.Signature = msSwapTwoMembers(reordered.Signature)
	out = append(out, reordered)

	// The covered signature stripped: sig2 covers a label that is not on the request.
	stripped := signed("broken_coverage_stripped", 0, agent, covering(broker))
	stripped.SignatureInput = msDropMember(stripped.SignatureInput, "sig1")
	stripped.Signature = msDropMember(stripped.Signature, "sig1")
	out = append(out, stripped)

	// Coverage of sig1's Signature member without its Signature-Input member.
	{
		req := msRequest(t, []string{msAuth})
		recs := signHopsOn(t, req, body, []hopSpec{agent})
		covered := append(coveredFor(req, "sig2"), signatureAgentComponent("sig1"), chainComponent("signature", "sig1"))
		recs = append(recs, signHopByHand(t, req, broker, "sig2", covered, signatureAgentMember("sig2", broker.directory)))
		out = append(out, mkMultisigVector("broken_coverage_without_signature_input", req, recs, body, 0))
	}
	// Coverage of sig1 that omits a component sig1 lists (sig1's own member).
	{
		req := msRequest(t, []string{msAuth})
		recs := signHopsOn(t, req, body, []hopSpec{agent})
		covered := append(coveredFor(req, "sig2"), chainComponent("signature", "sig1"), chainComponent("signature-input", "sig1"))
		recs = append(recs, signHopByHand(t, req, broker, "sig2", covered, signatureAgentMember("sig2", broker.directory)))
		out = append(out, mkMultisigVector("broken_coverage_missing_component", req, recs, body, 0))
	}

	// A broker signature that covers the AGENT's member: it is resolved in the
	// agent's directory, where the broker's key is not published.
	{
		req := msRequest(t, []string{msAuth})
		recs := signHopsOn(t, req, body, []hopSpec{agent})
		covered := append(plainComponents(requiredCoveredComponents...), signatureAgentComponent("sig1"))
		recs = append(recs, signHopByHand(t, req, broker, "sig2", covered, signatureAgentMember("sig2", broker.directory)))
		out = append(out, mkMultisigVector("wrong_directory_member", req, recs, body, 0))
	}
	// The legacy String form cannot name two directories: refused on a request
	// carrying two signatures.
	{
		req := msRequest(t, []string{msAuth})
		req.Header.Set("Content-Digest", ContentDigest(body))
		req.Header.Set(SignatureAgentHeader, `"`+agent.directory+`"`)
		legacy := append(plainComponents(requiredCoveredComponents...), CoveredComponent{Name: signatureAgentLower})
		recs := []multisigHop{signHopByHand(t, req, agent, "sig1", legacy, "")}
		recs = append(recs, signHopByHand(t, req, broker, "sig2", legacy, ""))
		out = append(out, mkMultisigVector("legacy_form_on_two_signatures", req, recs, body, 0))
	}

	// sig1's bytes corrupted: independent, and under a covering sig2.
	tamperedIndep := signed("tampered_first_independent", 0, agent, broker)
	tamperedIndep.Signature = msCorruptFirstMember(tamperedIndep.Signature)
	out = append(out, tamperedIndep)
	tamperedCov := signed("tampered_first_covered", 0, agent, covering(broker))
	tamperedCov.Signature = msCorruptFirstMember(tamperedCov.Signature)
	out = append(out, tamperedCov)
	// sig2's member repointed at another directory after signing.
	repointed := signed("repointed_second_member", 0, agent, broker)
	repointed.SignatureAgent = strings.Replace(repointed.SignatureAgent, broker.directory, "https://evil.example", 1)
	out = append(out, repointed)

	// Signed over an EMPTY Authorization, then missing a covered header: refused,
	// and noticed after the budget and the coverage check, so an over-budget or
	// reordered request keeps ITS reason. Bound EMPTY so that only a port telling
	// absent from empty refuses.
	emptySigned := func(name string, maxSig int, hops ...hopSpec) multisigChainVector {
		req := msRequest(t, []string{""})
		recs := signHopsOn(t, req, body, hops)
		return mkMultisigVector(name, req, recs, body, maxSig)
	}
	absentTwo := emptySigned("absent_authorization_two", 0, agent, covering(broker))
	absentTwo.OmitHeaders = []string{"Authorization"}
	absentOver := emptySigned("absent_authorization_over_budget", 2, agent, covering(broker), covering(relay))
	absentOver.OmitHeaders = []string{"Authorization"}
	absentReordered := emptySigned("absent_signature_agent_reordered", 0, agent, covering(broker))
	absentReordered.SignatureInput = msSwapTwoMembers(absentReordered.SignatureInput)
	absentReordered.Signature = msSwapTwoMembers(absentReordered.Signature)
	absentReordered.OmitHeaders = []string{SignatureAgentHeader}
	out = append(out, absentTwo, absentOver, absentReordered)

	// A second Authorization line beside the signed one, in another spelling: both
	// join, the covered value changes, the request is refused.
	dup := emptySigned("duplicate_authorization_two", 0, agent, covering(broker))
	dup.ExtraHeaders = map[string]string{"Authorization": "Bearer unsigned-token"}
	// The same request reached through conventionally spelled header names: a pure
	// case change, which the oracle still verifies.
	canon := signed("canonical_case_two", 0, agent, covering(broker))
	canon.OmitHeaders = []string{"Authorization", SignatureAgentHeader}
	canon.ExtraHeaders = map[string]string{"Authorization": msAuth, SignatureAgentHeader: canon.SignatureAgent}
	// Signed over TWO Authorization field lines: the covered value is the join, so
	// only a reader that joins reconstructs the base.
	{
		req := msRequest(t, []string{"Bearer first-line", "Bearer second-line"})
		recs := signHopsOn(t, req, body, []hopSpec{agent, covering(broker)})
		v := mkMultisigVector("duplicate_bound_two", req, recs, body, 0)
		v.ExtraHeaders = map[string]string{"Authorization": "Bearer second-line"}
		out = append(out, dup, canon, v)
	}

	for i := range out {
		keyids, dirs, reason := multisigOracleOutcome(t, out[i])
		out[i].ExpectedKeyIDs, out[i].ExpectedDirectories, out[i].ExpectedReason = keyids, dirs, reason
		out[i].ExpectedVerified = reason == ""
	}
	return out
}

func chainComponent(name, label string) CoveredComponent {
	return CoveredComponent{Name: name, Params: []ComponentParam{{Key: "key", Val: label}}}
}

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
// budget, returning the verified keyids and directories on success or the
// classified reject reason.
func multisigOracleOutcome(t *testing.T, v multisigChainVector) (keyids, dirs []string, reason string) {
	t.Helper()
	body, err := hex.DecodeString(v.BodyHex)
	if err != nil {
		t.Fatalf("%s: decode body: %v", v.Name, err)
	}
	req, err := http.NewRequest(v.Method, v.URL, nil)
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
		return nil, nil, classifyNegReason(verr)
	}
	for i := range verified {
		keyids = append(keyids, verified[i].KeyID)
		dirs = append(dirs, verified[i].SignatureAgent)
	}
	return keyids, dirs, ""
}

// verifyMultisigChainVector is the self-consistency guard: it re-runs the oracle
// over the emitted vector and asserts the recorded outcome matches.
func verifyMultisigChainVector(t *testing.T, v multisigChainVector) {
	t.Helper()
	keyids, dirs, reason := multisigOracleOutcome(t, v)
	if reason != v.ExpectedReason || (reason == "") != v.ExpectedVerified ||
		strings.Join(keyids, ",") != strings.Join(v.ExpectedKeyIDs, ",") ||
		strings.Join(dirs, ",") != strings.Join(v.ExpectedDirectories, ",") {
		t.Fatalf("chain vector %s: oracle (%q, %v, %v), recorded (%q, %v, %v)", v.Name,
			reason, keyids, dirs, v.ExpectedReason, v.ExpectedKeyIDs, v.ExpectedDirectories)
	}
}

// --- structured-field member surgery (comma-separated, ", " join) ---

func msDropMember(raw, label string) string {
	var members []string
	for _, m := range strings.Split(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(m), label+"=") {
			continue
		}
		members = append(members, m)
	}
	return strings.Join(members, ", ")
}

func msSwapTwoMembers(raw string) string {
	parts := strings.SplitN(raw, ", ", 2)
	if len(parts) != 2 {
		return raw
	}
	return parts[1] + ", " + parts[0]
}

// msCorruptFirstMember flips the first base64 char after the opening colon of the
// first Signature dictionary member — corrupting sig1's bytes while keeping the
// wire form well-formed, so the reject is a signature failure, not a parse error.
func msCorruptFirstMember(sig string) string {
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

// TestGenerateMultisigChainVectors emits the multi-signature golden corpus. Like TestGenerateVectors it is a verification no-op by default (asserts
// the committed file matches a fresh emit) and (re)writes it under
// FORA_UPDATE_VECTORS=1 — the emitter is both generator and drift gate.
func TestGenerateMultisigChainVectors(t *testing.T) {
	vectors := buildMultisigChainVectors(t)
	for _, v := range vectors {
		verifyMultisigChainVector(t, v)
	}
	path := filepath.Join("testdata", "multisig-chain-vectors.json")
	doc := map[string]any{"vectors": vectors}

	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
