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
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// ExpectedAcceptSignature is the Accept-Signature value the refusal carries
	// ("" for none). A refusal of a Signature-Agent form carries one, a tampered
	// or misdirected signature does not, so a replay that asserts it cannot pass
	// a tamper row on a Signature-Agent refusal.
	ExpectedAcceptSignature string `json:"expected_accept_signature,omitempty"`
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
	// originForm writes the member as the bare origin, see inOriginForm.
	originForm bool
}

// inOriginForm makes h sign its member as its bare origin, sig<N>="https://<host>",
// the form SDK v1.2 and earlier sent and every FORA verifier completes to the
// well-known key directory URL. The SDK signer now writes the URL, so such a hop
// is signed through appendChecked, which writes the value as given. A negative row
// signed this way is refused for the check it tests by a reader of either form, so
// the Python and TypeScript replays reach that check before their readers move to
// WG-01.
func (h hopSpec) inOriginForm() hopSpec {
	h.originForm = true
	return h
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
		switch {
		case h.originForm:
			opts.Label, sign = nextFreeLabel(req.Header), appendChecked
		case i == 0:
			sign = SignRequest
		}
		if err := sign(context.Background(), req, body, signer, opts); err != nil {
			t.Fatalf("hop %d: %v", i, err)
		}
		out = append(out, h.record(t))
	}
	return out
}

// signHopsInOriginForm is signHopsOn with every hop in the origin form.
func signHopsInOriginForm(t *testing.T, req *http.Request, body []byte, hops []hopSpec) []multisigHop {
	t.Helper()
	origin := make([]hopSpec, len(hops))
	for i, h := range hops {
		origin[i] = h.inOriginForm()
	}
	return signHopsOn(t, req, body, origin)
}

// originFormNegatives are refused chains whose check sits past the member rule:
// sig1's bytes corrupted (independent, and under a covering sig2), sig2's member
// repointed at another directory after signing, and a chain signed over an EMPTY
// Authorization that is then missing it, or carries a second line beside it in
// another spelling. Each is signed over bare origins, so a reader that has not
// moved to WG-01 reaches the check each row tests.
func originFormNegatives(t *testing.T, body []byte, agent, broker hopSpec) []multisigChainVector {
	t.Helper()
	sign := func(name string, authorization string, hops ...hopSpec) multisigChainVector {
		req := msRequest(t, []string{authorization})
		recs := signHopsInOriginForm(t, req, body, hops)
		return mkMultisigVector(name, req, recs, body, 0)
	}
	coveringBroker := broker
	coveringBroker.cover = true
	tamperedIndep := sign("tampered_first_independent", msAuth, agent, broker)
	tamperedIndep.Signature = msCorruptFirstMember(tamperedIndep.Signature)
	tamperedCov := sign("tampered_first_covered", msAuth, agent, coveringBroker)
	tamperedCov.Signature = msCorruptFirstMember(tamperedCov.Signature)
	repointed := sign("repointed_second_member", msAuth, agent, broker)
	repointed.SignatureAgent = strings.Replace(repointed.SignatureAgent, broker.directory, "https://evil.example", 1)
	absent := sign("absent_authorization_two", "", agent, coveringBroker)
	absent.OmitHeaders = []string{"Authorization"}
	dup := sign("duplicate_authorization_two", "", agent, coveringBroker)
	dup.ExtraHeaders = map[string]string{"Authorization": "Bearer unsigned-token"}
	return []multisigChainVector{tamperedIndep, tamperedCov, repointed, absent, dup}
}

// signHopByHand appends a signature labelled label made by h over exactly
// covered, adding memberHeader (when non-empty) to Signature-Agent first. It
// builds the signatures the appender refuses to make.
func signHopByHand(
	t *testing.T,
	req *http.Request,
	h hopSpec,
	label string,
	covered []CoveredComponent,
	memberHeader string,
) multisigHop {
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
		recs = append(
			recs,
			signHopByHand(t, req, broker, "sig2", covered, signatureAgentMember("sig2", broker.directory)),
		)
		out = append(out, mkMultisigVector("broken_coverage_without_signature_input", req, recs, body, 0))
	}
	// Coverage of sig1 that omits a component sig1 lists (sig1's own member).
	{
		req := msRequest(t, []string{msAuth})
		recs := signHopsOn(t, req, body, []hopSpec{agent})
		covered := append(
			coveredFor(req, "sig2"),
			chainComponent("signature", "sig1"),
			chainComponent("signature-input", "sig1"),
		)
		recs = append(
			recs,
			signHopByHand(t, req, broker, "sig2", covered, signatureAgentMember("sig2", broker.directory)),
		)
		out = append(out, mkMultisigVector("broken_coverage_missing_component", req, recs, body, 0))
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

	// A broker signature that covers the AGENT's member: resolved in the agent's
	// directory, where the broker's key is not published. Signed over bare origins,
	// like the refused chains below.
	{
		req := msRequest(t, []string{msAuth})
		recs := signHopsInOriginForm(t, req, body, []hopSpec{agent})
		covered := append(plainComponents(requiredCoveredComponents...), signatureAgentComponent("sig1"))
		recs = append(recs, signHopByHand(t, req, broker, "sig2", covered,
			signatureAgentMember("sig2", broker.directory)))
		out = append(out, mkMultisigVector("wrong_directory_member", req, recs, body, 0))
	}
	// The refused chains whose check sits past the member rule, over bare origins.
	out = append(out, originFormNegatives(t, body, agent, broker)...)

	// Signed over an EMPTY Authorization, then missing a covered header: refused,
	// and noticed after the budget and the coverage check, so an over-budget or
	// reordered request keeps ITS reason. Bound EMPTY so that only a port telling
	// absent from empty refuses.
	emptySigned := func(name string, maxSig int, hops ...hopSpec) multisigChainVector {
		req := msRequest(t, []string{""})
		recs := signHopsOn(t, req, body, hops)
		return mkMultisigVector(name, req, recs, body, maxSig)
	}
	absentOver := emptySigned("absent_authorization_over_budget", 2, agent, covering(broker), covering(relay))
	absentOver.OmitHeaders = []string{"Authorization"}
	absentReordered := emptySigned("absent_signature_agent_reordered", 0, agent, covering(broker))
	absentReordered.SignatureInput = msSwapTwoMembers(absentReordered.SignatureInput)
	absentReordered.Signature = msSwapTwoMembers(absentReordered.Signature)
	absentReordered.OmitHeaders = []string{SignatureAgentHeader}
	out = append(out, absentOver, absentReordered)

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
		out = append(out, canon, v)
	}

	for i := range out {
		keyids, dirs, reason, accept := multisigOracleOutcome(t, out[i])
		out[i].ExpectedKeyIDs, out[i].ExpectedDirectories, out[i].ExpectedReason = keyids, dirs, reason
		out[i].ExpectedAcceptSignature = accept
		out[i].ExpectedVerified = reason == ""
	}
	return out
}

func chainComponent(name, label string) CoveredComponent {
	return CoveredComponent{Name: name, Params: []ComponentParam{{Key: "key", Val: label}}}
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
