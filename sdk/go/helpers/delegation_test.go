package helpers

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Fixed scenario shared by the chain tests: an issuer, a principal, an agent, a
// sub-agent and the agent's holder key, all from fixed seeds, verified at a
// fixed clock. exp is one hour after that clock.
var (
	dIssuerPub, dIssuerPriv   = delegationTestKey(0xD1)
	dPrincipalPub, dPrincipal = delegationTestKey(0xD2)
	dAgentPub, dAgent         = delegationTestKey(0xD3)
	dSubPub, dSub             = delegationTestKey(0xD4)
	dHolderPub, _             = delegationTestKey(0xD5)
	dOtherPub, dOther         = delegationTestKey(0xD6)
	dNow                      = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	dExp                      = float64(dNow.Add(time.Hour).Unix())
	dAud                      = []string{"exchange.example"}
)

func dInput(t *testing.T, token string) DelegationInput {
	t.Helper()
	return DelegationInput{
		Token:          []byte(token),
		TrustedIssuers: []TrustedIssuer{{Identity: "marketdata.example", Key: dIssuerPub}},
		Audience:       "exchange.example",
		Holder:         mustThumbprint(t, dHolderPub),
		Now:            dNow,
	}
}

func dVerify(t *testing.T, token string) (*VerifiedDelegation, error) {
	t.Helper()
	return VerifyDelegation(dInput(t, token))
}

func wantFailure(t *testing.T, err error, f DelegationFailure) {
	t.Helper()
	var de *DelegationError
	if !errors.As(err, &de) {
		t.Fatalf("want DelegationError %s, got %v", f, err)
	}
	if de.Failure != f {
		t.Fatalf("want failure %s, got %s (%v)", f, de.Failure, err)
	}
	if !errors.Is(err, ErrDelegationInvalid) {
		t.Fatal("DelegationError must unwrap to ErrDelegationInvalid")
	}
}

func TestVerifyDelegation_ChainsThatPass(t *testing.T) {
	keys := []ed25519.PrivateKey{dIssuerPriv, dPrincipal, dAgent, dSub}
	cases := []struct {
		name  string
		depth int
		specs []tokenSpec
		want  []string
	}{
		{"root_only_eddsa", 1, []tokenSpec{{}}, []string{"earnings:*", "quote:*"}},
		{"two_tokens_child_ed25519", 2, []tokenSpec{{}, {alg: "Ed25519", claims: map[string]any{"scope": "earnings:*"}}}, []string{"earnings:*"}},
		{"mixed_root_ed25519_child_eddsa", 2, []tokenSpec{{alg: "Ed25519"}, {claims: map[string]any{"scope": "quote:AAPL"}}}, []string{"quote:AAPL"}},
		{"four_tokens", 4, []tokenSpec{{}, {}, {alg: "Ed25519"}, {claims: map[string]any{"scope": "earnings:q1"}}}, []string{"earnings:q1"}},
		{"child_narrows_wildcard", 2, []tokenSpec{{claims: map[string]any{"scope": "publisher:*:read"}}, {claims: map[string]any{"scope": "publisher:news:read"}}}, []string{"publisher:news:read"}},
		{"child_without_scope_grants_nothing", 2, []tokenSpec{{}, {claims: map[string]any{"scope": nil}}}, nil},
		{"advisory_ignored_jti_nbf_iat_sub_accepted", 1, []tokenSpec{{claims: map[string]any{
			"jti": "md-1", "nbf": dExp - 7200, "iat": dExp - 3600, "sub": "acme",
			"fora_advisory": map[string]any{"vendor": "x", "plan": map[string]any{"tier": 2}},
		}}}, []string{"earnings:*", "quote:*"}},
		{"root_jwk_ignored", 1, []tokenSpec{{header: map[string]any{"jwk": publicJWK(dOtherPub)}}}, []string{"earnings:*", "quote:*"}},
		{"kid_ignored", 1, []tokenSpec{{header: map[string]any{"kid": "md-2026"}}}, []string{"earnings:*", "quote:*"}},
		{"aud_string_and_443_folds", 1, []tokenSpec{{claims: map[string]any{"aud": "Exchange.Example:443"}}}, []string{"earnings:*", "quote:*"}},
		{"child_drops_an_audience", 2, []tokenSpec{{claims: map[string]any{"aud": []string{"exchange.example", "eu.exchange.example"}}}, {}}, []string{"earnings:*", "quote:*"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := mintChain(t, keys[:c.depth], dHolderPub, "marketdata.example", dAud, "quote:* earnings:*", dExp, c.specs)
			got, err := dVerify(t, tok)
			if err != nil {
				t.Fatal(err)
			}
			if got.RootIssuer != "marketdata.example" || got.Holder != mustThumbprint(t, dHolderPub) || got.Depth != c.depth {
				t.Fatalf("unexpected result %+v", got)
			}
			if strings.Join(got.Scopes, " ") != strings.Join(c.want, " ") {
				t.Fatalf("scopes = %v, want %v", got.Scopes, c.want)
			}
			if !got.ExpiresAt.Equal(dNow.Add(time.Hour)) {
				t.Fatalf("expiry = %v", got.ExpiresAt)
			}
		})
	}
}

func TestVerifyDelegation_EffectiveExpiryIsTheEarliest(t *testing.T) {
	keys := []ed25519.PrivateKey{dIssuerPriv, dPrincipal, dAgent}
	tok := mintChain(t, keys, dHolderPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{
		{}, {claims: map[string]any{"exp": dExp - 600}}, {claims: map[string]any{"exp": dExp - 600}},
	})
	got, err := dVerify(t, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.Equal(dNow.Add(50 * time.Minute)) {
		t.Fatalf("expiry = %v, want the children's", got.ExpiresAt)
	}
}

func TestVerifyDelegation_Refusals(t *testing.T) {
	keys := []ed25519.PrivateKey{dIssuerPriv, dPrincipal, dAgent, dSub}
	root1 := func(spec tokenSpec) string {
		return mintChain(t, keys[:1], dHolderPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{spec})
	}
	chain2 := func(rootSpec, childSpec tokenSpec) string {
		return mintChain(t, keys[:2], dHolderPub, "marketdata.example", dAud, "quote:* publisher:*:read", dExp, []tokenSpec{rootSpec, childSpec})
	}
	ecJWK := map[string]any{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
	ed448JWK := map[string]any{"kty": "OKP", "crv": "Ed448", "x": strings.Repeat("A", 76)}
	cases := []struct {
		name  string
		token string
		want  DelegationFailure
	}{
		{"not_a_jws", "abc", DelegationMalformed},
		{"alg_es256", root1(tokenSpec{alg: "ES256"}), DelegationBadAlg},
		{"typ_missing", root1(tokenSpec{header: map[string]any{"typ": nil}}), DelegationBadTyp},
		{"typ_jwt", root1(tokenSpec{header: map[string]any{"typ": "JWT"}}), DelegationBadTyp},
		{"crit_present", root1(tokenSpec{header: map[string]any{"crit": []string{"b64"}, "b64": false}}), DelegationCritPresent},
		{"iss_missing", root1(tokenSpec{claims: map[string]any{"iss": nil}}), DelegationMissingClaim},
		{"aud_missing", root1(tokenSpec{claims: map[string]any{"aud": nil}}), DelegationMissingClaim},
		{"cnf_missing", root1(tokenSpec{claims: map[string]any{"cnf": nil}}), DelegationMissingClaim},
		{"exp_missing", root1(tokenSpec{claims: map[string]any{"exp": nil}}), DelegationMissingClaim},
		{"exp_string", root1(tokenSpec{claims: map[string]any{"exp": "1781787345"}}), DelegationBadClaim},
		{"nbf_string", root1(tokenSpec{claims: map[string]any{"nbf": "soon"}}), DelegationBadClaim},
		{"jti_empty", root1(tokenSpec{claims: map[string]any{"jti": ""}}), DelegationBadClaim},
		{"aud_not_bare_host", root1(tokenSpec{claims: map[string]any{"aud": "https://exchange.example"}}), DelegationBadClaim},
		{"aud_empty_array", root1(tokenSpec{claims: map[string]any{"aud": []string{}}}), DelegationBadClaim},
		{"cnf_jkt_not_thumbprint", root1(tokenSpec{claims: map[string]any{"cnf": map[string]any{"jkt": "short"}}}), DelegationBadClaim},
		{"unknown_claim", root1(tokenSpec{claims: map[string]any{"vendor:plan": "gold"}}), DelegationUnknownClaim},
		{"spend_cap_unsupported", root1(tokenSpec{claims: map[string]any{"fora_max_spend_cents": 50000}}), DelegationUnsupportedRestriction},
		{"access_cap_unsupported", root1(tokenSpec{claims: map[string]any{"fora_max_accesses": 10}}), DelegationUnsupportedRestriction},
		{"advisory_shadows_scope", root1(tokenSpec{claims: map[string]any{"fora_advisory": map[string]any{"scope": "*"}}}), DelegationAdvisoryShadowsClaim},
		{"advisory_not_object", root1(tokenSpec{claims: map[string]any{"fora_advisory": "x"}}), DelegationBadClaim},
		{"untrusted_issuer", root1(tokenSpec{claims: map[string]any{"iss": "other.example"}}), DelegationUntrustedIssuer},
		{"root_signed_by_other_key", mintChain(t, []ed25519.PrivateKey{dOther}, dHolderPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{}}), DelegationBadSignature},
		{"expired_at_leeway_boundary", root1(tokenSpec{claims: map[string]any{"exp": float64(dNow.Unix()) - 60}}), DelegationExpired},
		{"not_yet_valid_beyond_leeway", root1(tokenSpec{claims: map[string]any{"nbf": float64(dNow.Unix()) + 61}}), DelegationNotYetValid},
		{"audience_other_recipient", root1(tokenSpec{claims: map[string]any{"aud": "eu.exchange.example"}}), DelegationAudienceMismatch},
		{"audience_other_port", root1(tokenSpec{claims: map[string]any{"aud": "exchange.example:8443"}}), DelegationAudienceMismatch},
		{"holder_mismatch", mintChain(t, keys[:1], dOtherPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{}}), DelegationHolderMismatch},
		{"child_without_jwk", chain2(tokenSpec{}, tokenSpec{header: map[string]any{"jwk": nil}}), DelegationBadJWK},
		{"child_jwk_ec", chain2(tokenSpec{}, tokenSpec{header: map[string]any{"jwk": ecJWK}}), DelegationBadJWK},
		{"child_jwk_ed448", chain2(tokenSpec{}, tokenSpec{header: map[string]any{"jwk": ed448JWK}}), DelegationBadJWK},
		{"child_jwk_not_parents_cnf", chain2(tokenSpec{}, tokenSpec{header: map[string]any{"jwk": publicJWK(dOtherPub)}}), DelegationJWKMismatch},
		{"child_iss_wrong_with_valid_linkage", chain2(tokenSpec{}, tokenSpec{claims: map[string]any{"iss": "acme"}}), DelegationChildIssuerMismatch},
		{"child_signed_by_other_key", forgedChild(t), DelegationBadSignature},
		{"child_exp_later_than_parent", chain2(tokenSpec{}, tokenSpec{claims: map[string]any{"exp": dExp + 1}}), DelegationExpiryWidened},
		{"child_adds_audience", chain2(tokenSpec{}, tokenSpec{claims: map[string]any{"aud": []string{"exchange.example", "eu.exchange.example"}}}), DelegationAudienceWidened},
		{"child_scope_outside_parent", chain2(tokenSpec{}, tokenSpec{claims: map[string]any{"scope": "credit:read"}}), DelegationScopeWidened},
		{"child_wildcard_widens_parent", chain2(tokenSpec{}, tokenSpec{claims: map[string]any{"scope": "publisher:news:*"}}), DelegationScopeWidened},
		{"child_scope_under_scopeless_parent", chain2(tokenSpec{claims: map[string]any{"scope": nil}}, tokenSpec{claims: map[string]any{"scope": "quote:*"}}), DelegationScopeWidened},
		{"five_tokens", mintChain(t, []ed25519.PrivateKey{dIssuerPriv, dPrincipal, dAgent, dSub, dOther}, dHolderPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{}, {}, {}, {}, {}}), DelegationTooDeep},
		{"fora_parent_not_a_jws", root1(tokenSpec{claims: map[string]any{"fora_parent": "nope"}}), DelegationMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := dVerify(t, c.token)
			wantFailure(t, err, c.want)
		})
	}
}

func TestVerifyDelegation_RawSyntax(t *testing.T) {
	// A valid root, as raw header and payload strings, then mutated below the
	// JSON layer: every mutation keeps a valid signature over the bytes sent.
	header := `{"alg":"EdDSA","typ":"fora-delegation+jwt"}`
	payload := `{"iss":"marketdata.example","aud":["exchange.example"],"exp":` + strconvF(dExp) + `,"scope":"quote:*","cnf":{"jkt":"` + mustThumbprint(t, dHolderPub) + `"}}`
	good := signCompactRaw(dIssuerPriv, header, payload)
	if _, err := dVerify(t, good); err != nil {
		t.Fatalf("baseline raw token must verify: %v", err)
	}
	cases := []struct {
		name  string
		token string
		want  DelegationFailure
	}{
		{"trailing_second_object", signCompactRaw(dIssuerPriv, header, payload+` {"scope":"*"}`), DelegationMalformed},
		{"trailing_garbage", signCompactRaw(dIssuerPriv, header, payload+`junk`), DelegationMalformed},
		{"payload_not_an_object", signCompactRaw(dIssuerPriv, header, `[1]`), DelegationMalformed},
		{"header_trailing_garbage", signCompactRaw(dIssuerPriv, header+`x`, payload), DelegationMalformed},
		{"b64_false_without_crit", signCompactRaw(dIssuerPriv, `{"alg":"EdDSA","typ":"fora-delegation+jwt","b64":false}`, payload), DelegationMalformed},
		{"crlf_after_signature", good + "\r\n", DelegationMalformed},
		{"crlf_inside_signature", good[:len(good)-4] + "\r\n" + good[len(good)-4:], DelegationMalformed},
		{"padded_segment", good + "=", DelegationMalformed},
		{"empty_segment", strings.Replace(good, ".", "..", 1), DelegationMalformed},
		{"exp_1e100", signCompactRaw(dIssuerPriv, header, strings.Replace(payload, strconvF(dExp), "1e100", 1)), DelegationBadClaim},
		{"exp_negative", signCompactRaw(dIssuerPriv, header, strings.Replace(payload, strconvF(dExp), "-1", 1)), DelegationBadClaim},
		{"nbf_beyond_range", signCompactRaw(dIssuerPriv, header, strings.Replace(payload, `"scope"`, `"nbf":253402300800,"scope"`, 1)), DelegationBadClaim},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := dVerify(t, c.token)
			wantFailure(t, err, c.want)
		})
	}
	max := signCompactRaw(dIssuerPriv, header, strings.Replace(payload, strconvF(dExp), "253402300799", 1))
	got, err := dVerify(t, max)
	if err != nil || got.ExpiresAt.Year() != 9999 {
		t.Fatalf("the largest NumericDate must verify and convert exactly: %v %v", got, err)
	}
}

func strconvF(f float64) string { return fmt.Sprintf("%d", int64(f)) }

func TestVerifyDelegation_SizeLimitBeforeParsing(t *testing.T) {
	in := dInput(t, strings.Repeat("a", MaxDelegationTokenBytes+1))
	_, err := VerifyDelegation(in)
	wantFailure(t, err, DelegationOversized)
	in.Token = []byte(strings.Repeat("a", MaxDelegationTokenBytes))
	_, err = VerifyDelegation(in)
	wantFailure(t, err, DelegationMalformed) // size passed, structure did not
}

func TestVerifyDelegation_ParentSubstitution(t *testing.T) {
	// A child minted under one root is re-attached to another valid root whose
	// cnf names a different principal: the child's jwk no longer matches.
	keys := []ed25519.PrivateKey{dIssuerPriv, dPrincipal}
	good := mintChain(t, keys, dHolderPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{}, {}})
	otherRoot := mintChain(t, []ed25519.PrivateKey{dIssuerPriv}, dOtherPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{}})
	child := mintChain(t, keys, dHolderPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{}, {claims: map[string]any{"fora_parent": otherRoot}}})
	if _, err := dVerify(t, good); err != nil {
		t.Fatal(err)
	}
	_, err := dVerify(t, child)
	wantFailure(t, err, DelegationJWKMismatch)
}

func TestVerifyDelegation_LeewayBoundaries(t *testing.T) {
	root := func(claims map[string]any) string {
		return mintChain(t, []ed25519.PrivateKey{dIssuerPriv}, dHolderPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{claims: claims}})
	}
	now := float64(dNow.Unix())
	if _, err := dVerify(t, root(map[string]any{"exp": now - 59})); err != nil {
		t.Fatalf("59s past exp is inside the leeway: %v", err)
	}
	got, err := dVerify(t, root(map[string]any{"exp": now - 59}))
	if err != nil || !got.ExpiresAt.Before(dNow) {
		t.Fatalf("leeway must not extend the returned expiry: %v %v", got, err)
	}
	if _, err := dVerify(t, root(map[string]any{"nbf": now + 60})); err != nil {
		t.Fatalf("nbf 60s ahead is inside the leeway: %v", err)
	}
}

func TestVerifyDelegation_ZeroNowIsTheCurrentTime(t *testing.T) {
	expired := float64(time.Now().Add(-365 * 24 * time.Hour).Unix())
	in := dInput(t, mintChain(t, []ed25519.PrivateKey{dIssuerPriv}, dHolderPub, "marketdata.example", dAud, "quote:*", expired, []tokenSpec{{}}))
	in.Now = time.Time{}
	_, err := VerifyDelegation(in)
	wantFailure(t, err, DelegationExpired)
}

func TestVerifyDelegation_BadAudienceConfiguration(t *testing.T) {
	in := dInput(t, "a.b.c")
	in.Audience = "https://exchange.example"
	_, err := VerifyDelegation(in)
	if !errors.Is(err, ErrAudienceIdentity) || errors.Is(err, ErrDelegationInvalid) {
		t.Fatalf("a bad verifier identity is a configuration error, not a refusal: %v", err)
	}
}

// forgedChild is a child whose jwk and iss name the principal the root's cnf
// names, but whose signature was made with another key: linkage looks right
// and only the signature check can refuse it.
func forgedChild(t *testing.T) string {
	t.Helper()
	root := mintChain(t, []ed25519.PrivateKey{dIssuerPriv}, dPrincipalPub, "marketdata.example", dAud, "quote:*", dExp, []tokenSpec{{}})
	return signCompact(t, dOther,
		map[string]any{"alg": "EdDSA", "typ": DelegationTokenType, "jwk": publicJWK(dPrincipalPub)},
		map[string]any{"iss": mustThumbprint(t, dPrincipalPub), "aud": dAud, "exp": dExp,
			"cnf": map[string]any{"jkt": mustThumbprint(t, dHolderPub)}, "scope": "quote:*", "fora_parent": root})
}
