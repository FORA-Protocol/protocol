package helpers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Delegation chain cases — shared, signed, with declared outcomes.
//
// TestGenerateDelegationChains mints every case from fixed seeds and a fixed
// clock and writes testdata/delegation-chains.json under FORA_UPDATE_VECTORS=1;
// otherwise it asserts the committed file matches a fresh emit. Every expected
// outcome is DECLARED in the case table from the profile text, never read back
// from VerifyDelegation; TestDelegationChainsReplay then drives the committed
// file through the verifier and fails on any disagreement. An Exchange's own
// tests, and the TypeScript and Python verifiers when they land, replay the same
// file. It is deliberately not named *-vectors.json: that suffix is the promise
// of tri-language replay, which the deferred ports cannot keep yet (see the
// delegation verifier DECISION in docs/sdk-parity-matrix.md).

type chainTrust struct {
	Identity string `json:"identity"`
	KeyX     string `json:"key_x"` // base64url Ed25519 public key, the OKP "x"
}

type chainMirrors struct {
	Issuer          string   `json:"issuer"`
	PrincipalDomain string   `json:"principal_domain"`
	Scopes          []string `json:"scopes"`
	ExpiresAt       string   `json:"expires_at"`
}

type chainExpect struct {
	Valid      bool     `json:"valid"`
	Failure    string   `json:"failure,omitempty"`
	RootIssuer string   `json:"root_issuer,omitempty"`
	Holder     string   `json:"holder,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Depth      int      `json:"depth,omitempty"`
}

type chainCase struct {
	Name     string        `json:"name"`
	Note     string        `json:"note"`
	Token    string        `json:"token"`
	Trusted  []chainTrust  `json:"trusted"`
	Audience string        `json:"audience"`
	Holder   string        `json:"holder"`
	Now      string        `json:"now"`
	Mirrors  *chainMirrors `json:"mirrors,omitempty"`
	Expect   chainExpect   `json:"expect"`
}

func buildDelegationChains(t *testing.T) []chainCase {
	t.Helper()
	issuerPub, issuer := delegationTestKey(0xA1)
	principalPub, principal := delegationTestKey(0xA2)
	agentPub, agent := delegationTestKey(0xA3)
	subPub, sub := delegationTestKey(0xA4)
	holderPub, _ := delegationTestKey(0xA5)
	otherPub, other := delegationTestKey(0xA6)
	_ = subPub
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	exp := float64(now.Add(time.Hour).Unix())
	expStr := now.Add(time.Hour).UTC().Format(time.RFC3339)
	nowStr := now.Format(time.RFC3339)
	nowF := float64(now.Unix())
	aud := []string{"exchange.example"}
	const iss = "marketdata.example"
	trusted := []chainTrust{{Identity: iss, KeyX: base64.RawURLEncoding.EncodeToString(issuerPub)}}
	holder := mustThumbprint(t, holderPub)
	thumb := func(pub ed25519.PublicKey) string { return mustThumbprint(t, pub) }
	keys := []ed25519.PrivateKey{issuer, principal, agent, sub}

	mint := func(depth int, scope string, specs ...tokenSpec) string {
		for len(specs) < depth {
			specs = append(specs, tokenSpec{})
		}
		return mintChain(t, keys[:depth], holderPub, iss, aud, scope, exp, specs)
	}
	ok := func(scopes []string, depth int) chainExpect {
		return chainExpect{Valid: true, RootIssuer: iss, Holder: holder, Scopes: scopes, ExpiresAt: expStr, Depth: depth}
	}
	okAt := func(scopes []string, depth int, expiresAt time.Time) chainExpect {
		e := ok(scopes, depth)
		e.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
		return e
	}
	fail := func(f DelegationFailure) chainExpect { return chainExpect{Valid: false, Failure: string(f)} }
	c := func(name, note, token string, expect chainExpect) chainCase {
		return chainCase{Name: name, Note: note, Token: token, Trusted: trusted, Audience: "exchange.example", Holder: holder, Now: nowStr, Expect: expect}
	}
	with := func(cc chainCase, f func(*chainCase)) chainCase { f(&cc); return cc }

	// Parent substitution: a child minted under a root that names the principal,
	// re-attached to a root that names another key.
	otherRoot := mintChain(t, keys[:1], otherPub, iss, aud, "quote:*", exp, []tokenSpec{{}})
	// A child whose linkage is right but whose signature was made with another key.
	rootForPrincipal := mintChain(t, keys[:1], principalPub, iss, aud, "quote:*", exp, []tokenSpec{{}})
	forged := signCompact(t, other,
		map[string]any{"alg": "EdDSA", "typ": DelegationTokenType, "jwk": publicJWK(principalPub)},
		map[string]any{"iss": thumb(principalPub), "aud": aud, "exp": exp, "cnf": map[string]any{"jkt": holder}, "scope": "quote:*", "fora_parent": rootForPrincipal})
	ecJWK := map[string]any{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}

	cases := []chainCase{
		c("root_only_eddsa", "one token, alg EdDSA, holder bound to the request key", mint(1, "quote:* earnings:*"), ok([]string{"earnings:*", "quote:*"}, 1)),
		c("root_only_ed25519", "one token, alg Ed25519 (RFC 9864)", mint(1, "quote:*", tokenSpec{alg: "Ed25519"}), ok([]string{"quote:*"}, 1)),
		c("two_tokens", "root EdDSA, child Ed25519 narrowing scope", mint(2, "quote:* earnings:*", tokenSpec{}, tokenSpec{alg: "Ed25519", claims: map[string]any{"scope": "earnings:*"}}), ok([]string{"earnings:*"}, 2)),
		c("two_tokens_mixed_reverse", "root Ed25519, child EdDSA", mint(2, "quote:*", tokenSpec{alg: "Ed25519"}, tokenSpec{}), ok([]string{"quote:*"}, 2)),
		c("three_tokens", "root, principal, agent", mint(3, "quote:*", tokenSpec{}, tokenSpec{}, tokenSpec{claims: map[string]any{"scope": "quote:AAPL"}}), ok([]string{"quote:AAPL"}, 3)),
		c("four_tokens", "the deepest chain the profile allows", mint(4, "quote:*", tokenSpec{}, tokenSpec{}, tokenSpec{}, tokenSpec{claims: map[string]any{"scope": "quote:AAPL"}}), ok([]string{"quote:AAPL"}, 4)),
		c("five_tokens", "a fifth token is never decoded", mintChain(t, []ed25519.PrivateKey{issuer, principal, agent, sub, other}, holderPub, iss, aud, "quote:*", exp, []tokenSpec{{}, {}, {}, {}, {}}), fail(DelegationTooDeep)),
		c("jti_present", "jti is recommended and checked for shape only", mint(1, "quote:*", tokenSpec{claims: map[string]any{"jti": "md-2026-000481"}}), ok([]string{"quote:*"}, 1)),
		c("jti_empty", "an empty jti is a bad claim", mint(1, "quote:*", tokenSpec{claims: map[string]any{"jti": ""}}), fail(DelegationBadClaim)),
		c("typ_missing", "typ fora-delegation+jwt is required on every token", mint(1, "quote:*", tokenSpec{header: map[string]any{"typ": nil}}), fail(DelegationBadTyp)),
		c("typ_wrong_on_child", "typ JWT on a child", mint(2, "quote:*", tokenSpec{}, tokenSpec{header: map[string]any{"typ": "JWT"}}), fail(DelegationBadTyp)),
		c("alg_es256", "only EdDSA and Ed25519 are accepted", mint(1, "quote:*", tokenSpec{alg: "ES256"}), fail(DelegationBadAlg)),
		c("crit_present", "the profile defines no critical header parameters", mint(1, "quote:*", tokenSpec{header: map[string]any{"crit": []string{"b64"}, "b64": false}}), fail(DelegationCritPresent)),
		c("iss_missing", "", mint(1, "quote:*", tokenSpec{claims: map[string]any{"iss": nil}}), fail(DelegationMissingClaim)),
		c("aud_missing", "", mint(1, "quote:*", tokenSpec{claims: map[string]any{"aud": nil}}), fail(DelegationMissingClaim)),
		c("cnf_missing", "", mint(1, "quote:*", tokenSpec{claims: map[string]any{"cnf": nil}}), fail(DelegationMissingClaim)),
		c("exp_missing", "", mint(1, "quote:*", tokenSpec{claims: map[string]any{"exp": nil}}), fail(DelegationMissingClaim)),
		c("exp_not_a_number", "exp as a string", mint(1, "quote:*", tokenSpec{claims: map[string]any{"exp": "1781787345"}}), fail(DelegationBadClaim)),
		c("exp_out_of_range", "exp 1e400 is not a finite number", mint(1, "quote:*", tokenSpec{claims: map[string]any{"exp": json.Number("1e400")}}), fail(DelegationBadClaim)),
		c("exp_inside_leeway", "59 seconds past exp is accepted; the returned expiry is still exp", mint(1, "quote:*", tokenSpec{claims: map[string]any{"exp": nowF - 59}}), okAt([]string{"quote:*"}, 1, now.Add(-59*time.Second))),
		c("exp_at_leeway", "60 seconds past exp is expired", mint(1, "quote:*", tokenSpec{claims: map[string]any{"exp": nowF - 60}}), fail(DelegationExpired)),
		c("nbf_inside_leeway", "nbf 60 seconds ahead is accepted", mint(1, "quote:*", tokenSpec{claims: map[string]any{"nbf": nowF + 60}}), ok([]string{"quote:*"}, 1)),
		c("nbf_beyond_leeway", "nbf 61 seconds ahead is not yet valid", mint(1, "quote:*", tokenSpec{claims: map[string]any{"nbf": nowF + 61}}), fail(DelegationNotYetValid)),
		c("child_expires_first", "the effective expiry is the earliest exp in the chain", mint(2, "quote:*", tokenSpec{}, tokenSpec{claims: map[string]any{"exp": exp - 600}}), okAt([]string{"quote:*"}, 2, now.Add(50*time.Minute))),
		c("audience_other_recipient", "aud names another Exchange", mint(1, "quote:*", tokenSpec{claims: map[string]any{"aud": "eu.exchange.example"}}), fail(DelegationAudienceMismatch)),
		c("audience_case_and_443_fold", "Exchange.Example:443 names exchange.example", mint(1, "quote:*", tokenSpec{claims: map[string]any{"aud": "Exchange.Example:443"}}), ok([]string{"quote:*"}, 1)),
		c("audience_not_bare_host", "a URL is not a recipient identity", mint(1, "quote:*", tokenSpec{claims: map[string]any{"aud": "https://exchange.example"}}), fail(DelegationBadClaim)),
		c("child_widens_audience", "a child adds a recipient its parent did not list", mint(2, "quote:*", tokenSpec{}, tokenSpec{claims: map[string]any{"aud": []string{"exchange.example", "eu.exchange.example"}}}), fail(DelegationAudienceWidened)),
		c("child_narrows_audience", "a child drops one of the parent's recipients", mint(2, "quote:*", tokenSpec{claims: map[string]any{"aud": []string{"exchange.example", "eu.exchange.example"}}}, tokenSpec{}), ok([]string{"quote:*"}, 2)),
		c("untrusted_root", "the root is signed by a key that is not configured", mintChain(t, []ed25519.PrivateKey{other}, holderPub, iss, aud, "quote:*", exp, []tokenSpec{{}}), fail(DelegationBadSignature)),
		c("root_iss_not_configured", "root iss names an identity with no configured key", mint(1, "quote:*", tokenSpec{claims: map[string]any{"iss": "other.example"}}), fail(DelegationUntrustedIssuer)),
		c("root_signature_tampered", "the root payload was changed after signing", tamperPayload(t, mint(1, "quote:*")), fail(DelegationBadSignature)),
		c("child_signature_tampered", "the child payload was changed after signing", tamperPayload(t, mint(2, "quote:*")), fail(DelegationBadSignature)),
		c("child_iss_wrong", "signature and jwk linkage are valid but iss is not the signing key's thumbprint", mint(2, "quote:*", tokenSpec{}, tokenSpec{claims: map[string]any{"iss": "acme"}}), fail(DelegationChildIssuerMismatch)),
		c("child_signed_by_other_key", "jwk and iss name the principal, the signature was made with another key", forged, fail(DelegationBadSignature)),
		c("parent_substituted", "a child re-attached to a different valid root", mint(2, "quote:*", tokenSpec{}, tokenSpec{claims: map[string]any{"fora_parent": otherRoot}}), fail(DelegationJWKMismatch)),
		c("child_jwk_not_parents_cnf", "the child's jwk is not the key the parent's cnf.jkt names", mint(2, "quote:*", tokenSpec{}, tokenSpec{header: map[string]any{"jwk": publicJWK(otherPub)}}), fail(DelegationJWKMismatch)),
		c("child_jwk_missing", "", mint(2, "quote:*", tokenSpec{}, tokenSpec{header: map[string]any{"jwk": nil}}), fail(DelegationBadJWK)),
		c("child_jwk_not_ed25519", "an EC P-256 jwk", mint(2, "quote:*", tokenSpec{}, tokenSpec{header: map[string]any{"jwk": ecJWK}}), fail(DelegationBadJWK)),
		c("root_jwk_ignored", "a jwk on the root is not read; the configured key verifies it", mint(1, "quote:*", tokenSpec{header: map[string]any{"jwk": publicJWK(otherPub)}}), ok([]string{"quote:*"}, 1)),
		c("holder_mismatch", "the terminal cnf.jkt is not the key the request proved", mintChain(t, keys[:1], agentPub, iss, aud, "quote:*", exp, []tokenSpec{{}}), fail(DelegationHolderMismatch)),
		c("oversized_token", "a token over 32768 bytes is refused before parsing", mint(1, "quote:*", tokenSpec{claims: map[string]any{"fora_advisory": map[string]any{"pad": strings.Repeat("a", MaxDelegationTokenBytes)}}}), fail(DelegationOversized)),
		c("child_scope_outside_parent", "", mint(2, "quote:*", tokenSpec{}, tokenSpec{claims: map[string]any{"scope": "credit:read"}}), fail(DelegationScopeWidened)),
		c("child_narrows_wildcard", "publisher:news:read under publisher:*:read", mint(2, "publisher:*:read", tokenSpec{}, tokenSpec{claims: map[string]any{"scope": "publisher:news:read"}}), ok([]string{"publisher:news:read"}, 2)),
		c("child_wildcard_widens_parent", "publisher:news:* under publisher:*:read", mint(2, "publisher:*:read", tokenSpec{}, tokenSpec{claims: map[string]any{"scope": "publisher:news:*"}}), fail(DelegationScopeWidened)),
		c("child_without_scope", "a child with no scope grants no scoped access and is still valid", mint(2, "quote:*", tokenSpec{}, tokenSpec{claims: map[string]any{"scope": nil}}), ok(nil, 2)),
		c("child_exp_later_than_parent", "", mint(2, "quote:*", tokenSpec{}, tokenSpec{claims: map[string]any{"exp": exp + 1}}), fail(DelegationExpiryWidened)),
		c("spend_cap_unsupported", "this verifier enforces no cap, so a cap claim is refused rather than dropped", mint(1, "quote:*", tokenSpec{claims: map[string]any{"fora_max_spend_cents": 50000}}), fail(DelegationUnsupportedRestriction)),
		c("unknown_claim", "a claim the profile does not list is a restriction the verifier cannot evaluate", mint(1, "quote:*", tokenSpec{claims: map[string]any{"vendor:plan": "gold"}}), fail(DelegationUnknownClaim)),
		c("advisory_unknown_content_ignored", "", mint(1, "quote:*", tokenSpec{claims: map[string]any{"fora_advisory": map[string]any{"vendor": "x", "plan": map[string]any{"tier": 2}}}}), ok([]string{"quote:*"}, 1)),
		c("advisory_shadows_profile_claim", "scope inside fora_advisory", mint(1, "quote:*", tokenSpec{claims: map[string]any{"fora_advisory": map[string]any{"scope": "*"}}}), fail(DelegationAdvisoryShadowsClaim)),
		with(c("mirrors_disagree_no_effect", "plaintext Delegation fields that disagree with the signed chain change nothing; an Exchange verifies the chain and never reads them for trust", mint(1, "quote:*"), ok([]string{"quote:*"}, 1)), func(e *chainCase) {
			e.Mirrors = &chainMirrors{Issuer: "attacker.example", PrincipalDomain: "attacker.example", Scopes: []string{"*"}, ExpiresAt: "2099-01-01T00:00:00Z"}
		}),
	}
	// Raw-byte syntax cases: a valid signature over bytes the JSON marshaller
	// never produces, so only the syntax checks can refuse them.
	rawHeader := `{"alg":"EdDSA","typ":"fora-delegation+jwt"}`
	rawPayload := `{"iss":"` + iss + `","aud":["exchange.example"],"exp":` + fmt.Sprintf("%d", int64(exp)) + `,"scope":"quote:*","cnf":{"jkt":"` + holder + `"}}`
	rawGood := signCompactRaw(issuer, rawHeader, rawPayload)
	cases = append(cases,
		c("raw_baseline", "the raw-signed root every raw syntax case starts from", rawGood, ok([]string{"quote:*"}, 1)),
		c("payload_trailing_object", "a second JSON object after the claims object, under a valid signature", signCompactRaw(issuer, rawHeader, rawPayload+` {"scope":"*"}`), fail(DelegationMalformed)),
		c("payload_trailing_text", "text after the claims object, under a valid signature", signCompactRaw(issuer, rawHeader, rawPayload+`junk`), fail(DelegationMalformed)),
		c("payload_not_object", "a JSON array as payload", signCompactRaw(issuer, rawHeader, `[1]`), fail(DelegationMalformed)),
		c("header_b64_false", "RFC 7797 b64:false without crit", signCompactRaw(issuer, `{"alg":"EdDSA","typ":"fora-delegation+jwt","b64":false}`, rawPayload), fail(DelegationMalformed)),
		c("signature_crlf", "CR LF appended to the signature segment", rawGood+"\r\n", fail(DelegationMalformed)),
		c("signature_padded", "a padding character in the signature segment", rawGood+"=", fail(DelegationMalformed)),
		c("exp_beyond_numeric_date_range", "exp 1e100 is finite but no date the profile can return", signCompactRaw(issuer, rawHeader, strings.Replace(rawPayload, fmt.Sprintf("%d", int64(exp)), "1e100", 1)), fail(DelegationBadClaim)),
		c("exp_negative", "", signCompactRaw(issuer, rawHeader, strings.Replace(rawPayload, fmt.Sprintf("%d", int64(exp)), "-1", 1)), fail(DelegationBadClaim)),
		c("exp_at_numeric_date_max", "253402300799 is the last accepted second", signCompactRaw(issuer, rawHeader, strings.Replace(rawPayload, fmt.Sprintf("%d", int64(exp)), "253402300799", 1)), okAt([]string{"quote:*"}, 1, time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))),
	)
	cases = append(cases, documentedChains(t)...)
	return cases
}

// documentedChains are the chains the documentation embeds as real tokens, with
// the identities, audiences and scopes the pages' stories use. The conformance
// test in conformance/docdelegation_test.go finds every documented token, looks
// its case up here by name, and verifies it with VerifyDelegation under the
// case's inputs, so a page can never show a token that does not verify.
func documentedChains(t *testing.T) []chainCase {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	nowStr := now.Format(time.RFC3339)
	trust := func(identity string, pub ed25519.PublicKey) []chainTrust {
		return []chainTrust{{Identity: identity, KeyX: base64.RawURLEncoding.EncodeToString(pub)}}
	}
	expect := func(iss, holder string, scopes []string, exp time.Time, depth int) chainExpect {
		return chainExpect{Valid: true, RootIssuer: iss, Holder: holder, Scopes: scopes, ExpiresAt: exp.UTC().Format(time.RFC3339), Depth: depth}
	}
	marketPub, market := delegationTestKey(0xB0)
	finbotPub, _ := delegationTestKey(0xB1)
	iamPub, iam := delegationTestKey(0xB2)
	legalPub, legal := delegationTestKey(0xB3)
	subAgentPub, _ := delegationTestKey(0xB4)
	hedgePub, _ := delegationTestKey(0xB5)
	stanfordPub, stanford := delegationTestKey(0xB6)
	litrevPub, _ := delegationTestKey(0xB7)

	hour := now.Add(time.Hour)
	yearEnd := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	return []chainCase{
		{
			Name: "docs_subscription_agent", Note: "authentication page, Subscription Agent example: a MarketData root token bound to FinBot's request key",
			Token:   mintChain(t, []ed25519.PrivateKey{market}, finbotPub, "marketdata.example.com", []string{"exchange.example"}, "subscription:marketdata-2026 quote:* earnings:*", float64(hour.Unix()), []tokenSpec{{claims: map[string]any{"jti": "md-sub-2026-0481"}}}),
			Trusted: trust("marketdata.example.com", marketPub), Audience: "exchange.example", Holder: mustThumbprint(t, finbotPub), Now: nowStr,
			Expect: expect("marketdata.example.com", mustThumbprint(t, finbotPub), []string{"earnings:*", "quote:*", "subscription:marketdata-2026"}, hour, 1),
		},
		{
			Name: "docs_enterprise_agent", Note: "authentication page, Enterprise Agent example: an IAM root token bound to the legal research agent's key",
			Token:   mintChain(t, []ed25519.PrivateKey{iam}, legalPub, "iam.kirkland.com", []string{"exchange.example"}, "legal:case-law legal:statutes credit:read", float64(hour.Unix()), []tokenSpec{{claims: map[string]any{"jti": "iam-7c1e", "sub": "user@kirkland.com"}}}),
			Trusted: trust("iam.kirkland.com", iamPub), Audience: "exchange.example", Holder: mustThumbprint(t, legalPub), Now: nowStr,
			Expect: expect("iam.kirkland.com", mustThumbprint(t, legalPub), []string{"credit:read", "legal:case-law", "legal:statutes"}, hour, 1),
		},
		{
			Name: "docs_delegated_sub_agent", Note: "authentication page, Delegated Sub-Agent example: the legal agent narrows the IAM grant to credit:read for a sub-agent, one hour shorter",
			Token: mintChain(t, []ed25519.PrivateKey{iam, legal}, subAgentPub, "iam.kirkland.com", []string{"exchange.example"}, "legal:case-law legal:statutes credit:read", float64(hour.Unix()), []tokenSpec{
				{claims: map[string]any{"jti": "iam-7c1e", "sub": "user@kirkland.com"}},
				{alg: "Ed25519", claims: map[string]any{"jti": "legal-sub-0007", "scope": "credit:read", "exp": float64(now.Add(30 * time.Minute).Unix())}},
			}),
			Trusted: trust("iam.kirkland.com", iamPub), Audience: "exchange.example", Holder: mustThumbprint(t, subAgentPub), Now: nowStr,
			Expect: expect("iam.kirkland.com", mustThumbprint(t, subAgentPub), []string{"credit:read"}, now.Add(30*time.Minute), 2),
		},
		{
			Name: "docs_walkthrough_v1", Note: "walkthrough v1 scenario B: the MarketData root token for the hedge fund's agent, addressed to exchange.marketdata-data.com",
			Token:   mintChain(t, []ed25519.PrivateKey{market}, hedgePub, "marketdata.example.com", []string{"exchange.marketdata-data.com"}, "quote:* earnings:* news:read subscription:enterprise-sub-HF-001", float64(yearEnd.Unix()), []tokenSpec{{claims: map[string]any{"jti": "md-hf-001-2026", "sub": "enterprise-sub-HF-001"}}}),
			Trusted: trust("marketdata.example.com", marketPub), Audience: "exchange.marketdata-data.com", Holder: mustThumbprint(t, hedgePub), Now: nowStr,
			Expect: expect("marketdata.example.com", mustThumbprint(t, hedgePub), []string{"earnings:*", "news:read", "quote:*", "subscription:enterprise-sub-HF-001"}, yearEnd, 1),
		},
		{
			Name: "docs_walkthrough_academic", Note: "academic walkthrough: Stanford's root token for the literature review agent, addressed to exchange.scholarsgate.com",
			Token:   mintChain(t, []ed25519.PrivateKey{stanford}, litrevPub, "stanford.edu", []string{"exchange.scholarsgate.com"}, "academic:*", float64(yearEnd.Unix()), []tokenSpec{{claims: map[string]any{"jti": "inst-sub-stanford-2026-0193", "sub": "inst-sub-stanford-2026"}}}),
			Trusted: trust("stanford.edu", stanfordPub), Audience: "exchange.scholarsgate.com", Holder: mustThumbprint(t, litrevPub), Now: nowStr,
			Expect: expect("stanford.edu", mustThumbprint(t, litrevPub), []string{"academic:*"}, yearEnd, 1),
		},
	}
}

// tamperPayload flips one character of the outer token's payload so the
// signature no longer covers what is read.
func tamperPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	// "quote" → "quotf": still valid JSON and a valid scope, only the bytes differ.
	changed := strings.Replace(string(payload), "quote", "quotf", 1)
	if changed == string(payload) {
		t.Fatal("payload had nothing to tamper")
	}
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(changed)) + "." + parts[2]
}

func TestGenerateDelegationChains(t *testing.T) {
	doc := map[string]any{"cases": buildDelegationChains(t)}
	path := filepath.Join("testdata", "delegation-chains.json")
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}

// TestDelegationChainsReplay drives the committed file through VerifyDelegation
// and compares with the declared outcome of every case.
func TestDelegationChainsReplay(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "delegation-chains.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []chainCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}
	var passed, refused int
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			in := DelegationInput{Token: []byte(c.Token), Audience: c.Audience, Holder: c.Holder}
			in.Now, err = time.Parse(time.RFC3339, c.Now)
			if err != nil {
				t.Fatal(err)
			}
			for _, tr := range c.Trusted {
				x, err := base64.RawURLEncoding.DecodeString(tr.KeyX)
				if err != nil {
					t.Fatal(err)
				}
				in.TrustedIssuers = append(in.TrustedIssuers, TrustedIssuer{Identity: tr.Identity, Key: ed25519.PublicKey(x)})
			}
			got, err := VerifyDelegation(in)
			if !c.Expect.Valid {
				refused++
				var de *DelegationError
				if !errors.As(err, &de) {
					t.Fatalf("expected refusal %s, got %v (%+v)", c.Expect.Failure, err, got)
				}
				if string(de.Failure) != c.Expect.Failure {
					t.Fatalf("expected failure %s, got %s: %v", c.Expect.Failure, de.Failure, err)
				}
				return
			}
			passed++
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if got.RootIssuer != c.Expect.RootIssuer || got.Holder != c.Expect.Holder || got.Depth != c.Expect.Depth ||
				strings.Join(got.Scopes, " ") != strings.Join(c.Expect.Scopes, " ") ||
				got.ExpiresAt.UTC().Format(time.RFC3339) != c.Expect.ExpiresAt {
				t.Fatalf("result %+v does not match the declared outcome %+v", got, c.Expect)
			}
		})
	}
	if passed == 0 || refused == 0 {
		t.Fatalf("cases must carry both outcomes; got %d/%d", passed, refused)
	}
}
