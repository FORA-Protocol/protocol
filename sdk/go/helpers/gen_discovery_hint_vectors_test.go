package helpers

// Discovery-hint golden-vector emitter.
//
// The edge discovery headers are an HTTP convention with no protovalidate rule
// behind them, so the only thing holding the three SDKs to one reading of a 403
// is this corpus. Every recorded state and agreement is derived by calling the
// real ParseDiscoveryHint and ReconcileDiscoveryHint. Each row still carries the
// answer its author intended, and the emitter refuses to write a file where the
// real face disagrees, so a face that drifted cannot publish its drift as the
// new expectation.
//
// Headers are recorded as ordered [name, value] pairs rather than an object, so
// a row can send a header twice and can spell a name in any case. A replay adds
// the pairs to its language's header type one by one.
//
// Verification no-op by default (asserts the committed file matches a fresh
// emit); (re)writes under FORA_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const (
	hintManifestURL = "https://publisher.example/.well-known/fora.json"
	hintExchange    = "exchange.example"
)

// hintExpectation is what ParseDiscoveryHint returns, as the tokens and values
// the corpus records. A value is "" whenever its state is not valid.
type hintExpectation struct {
	ContentRules      string `json:"content_rules"`
	ContentRulesState string `json:"content_rules_state"`
	Exchange          string `json:"exchange"`
	ExchangeState     string `json:"exchange_state"`
}

// discoveryHintParseVector is one ParseDiscoveryHint case.
type discoveryHintParseVector struct {
	Name     string          `json:"name"`
	Status   int             `json:"status"`
	Headers  [][2]string     `json:"headers"`
	Expected hintExpectation `json:"expected"`
}

// discoveryHintReconcileVector is one ParseDiscoveryHint-then-ReconcileDiscoveryHint
// case: the 403's headers, the Exchange domains the publisher manifest lists, and
// the agreement token.
type discoveryHintReconcileVector struct {
	Name      string      `json:"name"`
	Status    int         `json:"status"`
	Headers   [][2]string `json:"headers"`
	Listed    []string    `json:"listed"`
	Agreement string      `json:"expected_agreement"`
}

func headerOf(pairs [][2]string) http.Header {
	h := http.Header{}
	for _, p := range pairs {
		h.Add(p[0], p[1])
	}
	return h
}

func expectationOf(h DiscoveryHint) hintExpectation {
	return hintExpectation{
		ContentRules:      h.ContentRules,
		ContentRulesState: h.ContentRulesState.String(),
		Exchange:          h.Exchange,
		ExchangeState:     h.ExchangeState.String(),
	}
}

func cr(v string) [2]string { return [2]string{ContentRulesHeader, v} }
func ex(v string) [2]string { return [2]string{ExchangeHeader, v} }

func validBoth() hintExpectation {
	return hintExpectation{hintManifestURL, "valid", hintExchange, "valid"}
}

func buildDiscoveryHintParseVectors(t *testing.T) []discoveryHintParseVector {
	t.Helper()
	const absent, malformed = "absent", "malformed"
	crMalformed := func(exchangeState, exchange string) hintExpectation {
		return hintExpectation{"", malformed, exchange, exchangeState}
	}
	exMalformed := hintExpectation{hintManifestURL, "valid", "", malformed}
	rows := []discoveryHintParseVector{
		// Both headers, valid.
		{"both_valid", 403, [][2]string{cr(hintManifestURL), ex(hintExchange)}, validBoth()},
		{"both_valid_with_ports", 403,
			[][2]string{cr("https://publisher.example:8443/.well-known/fora.json"), ex("exchange.example:8081")},
			hintExpectation{"https://publisher.example:8443/.well-known/fora.json", "valid", "exchange.example:8081", "valid"}},
		{"header_names_any_case", 403,
			[][2]string{{"x-content-rules", hintManifestURL}, {"X-FORA-EXCHANGE", hintExchange}}, validBoth()},
		{"surrounding_whitespace_trimmed", 403,
			[][2]string{cr(" " + hintManifestURL + "\t"), ex("  " + hintExchange + " ")}, validBoth()},
		{"plaintext_scheme_is_a_transport_question", 403,
			[][2]string{cr("http://publisher.example:8080/.well-known/fora.json"), ex(hintExchange)},
			hintExpectation{"http://publisher.example:8080/.well-known/fora.json", "valid", hintExchange, "valid"}},
		{"exchange_kept_as_sent", 403, [][2]string{cr(hintManifestURL), ex("Exchange.Example:443")},
			hintExpectation{hintManifestURL, "valid", "Exchange.Example:443", "valid"}},

		// One header missing.
		{"exchange_missing", 403, [][2]string{cr(hintManifestURL)},
			hintExpectation{hintManifestURL, "valid", "", absent}},
		{"content_rules_missing", 403, [][2]string{ex(hintExchange)},
			hintExpectation{"", absent, hintExchange, "valid"}},
		{"neither_header", 403, [][2]string{{"Content-Type", "application/json"}},
			hintExpectation{"", absent, "", absent}},

		// The headers mean something only on a 403.
		{"status_200_ignored", 200, [][2]string{cr(hintManifestURL), ex(hintExchange)},
			hintExpectation{"", absent, "", absent}},
		{"status_401_ignored", 401, [][2]string{cr(hintManifestURL), ex(hintExchange)},
			hintExpectation{"", absent, "", absent}},
		{"status_402_ignored", 402, [][2]string{cr(hintManifestURL), ex(hintExchange)},
			hintExpectation{"", absent, "", absent}},
		{"status_404_ignored", 404, [][2]string{cr(hintManifestURL), ex(hintExchange)},
			hintExpectation{"", absent, "", absent}},

		// X-Content-Rules malformed. Each header is judged on its own, so the
		// valid X-FORA-Exchange beside it survives.
		{"content_rules_points_at_an_exchange", 403,
			[][2]string{cr("https://exchange.example/v1/info"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_relative", 403,
			[][2]string{cr(WellKnownPath), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_schemeless", 403,
			[][2]string{cr("publisher.example/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_scheme_relative", 403,
			[][2]string{cr("//publisher.example/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_other_scheme", 403,
			[][2]string{cr("ftp://publisher.example/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_uppercase_scheme", 403,
			[][2]string{cr("HTTPS://publisher.example/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_other_path", 403,
			[][2]string{cr("https://publisher.example/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_path_prefix", 403,
			[][2]string{cr("https://publisher.example/x/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_trailing_slash", 403,
			[][2]string{cr(hintManifestURL + "/"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_query", 403,
			[][2]string{cr(hintManifestURL + "?v=1"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_fragment", 403,
			[][2]string{cr(hintManifestURL + "#terms"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_userinfo", 403,
			[][2]string{cr("https://agent@publisher.example/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_ipv6_literal", 403,
			[][2]string{cr("https://[::1]/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_trailing_root_dot", 403,
			[][2]string{cr("https://publisher.example./.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_bad_port", 403,
			[][2]string{cr("https://publisher.example:0/.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_no_host", 403,
			[][2]string{cr("https:///.well-known/fora.json"), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_empty", 403,
			[][2]string{cr(""), ex(hintExchange)}, crMalformed("valid", hintExchange)},
		{"content_rules_sent_twice", 403,
			[][2]string{cr(hintManifestURL), cr("https://other.example/.well-known/fora.json"), ex(hintExchange)},
			crMalformed("valid", hintExchange)},
		{"content_rules_comma_list", 403,
			[][2]string{cr(hintManifestURL + ", https://other.example/.well-known/fora.json")}, crMalformed(absent, "")},

		// X-FORA-Exchange malformed.
		{"exchange_is_a_url", 403, [][2]string{cr(hintManifestURL), ex("https://exchange.example")}, exMalformed},
		{"exchange_has_a_path", 403, [][2]string{cr(hintManifestURL), ex("exchange.example/v1")}, exMalformed},
		{"exchange_endpoint_url", 403,
			[][2]string{cr(hintManifestURL), ex("https://exchange.example/fora.v1.ExchangeService")}, exMalformed},
		{"exchange_underscore", 403, [][2]string{cr(hintManifestURL), ex("ex_change.example")}, exMalformed},
		{"exchange_port_out_of_range", 403, [][2]string{cr(hintManifestURL), ex("exchange.example:65536")}, exMalformed},
		{"exchange_trailing_root_dot", 403, [][2]string{cr(hintManifestURL), ex("exchange.example.")}, exMalformed},
		{"exchange_non_ascii", 403, [][2]string{cr(hintManifestURL), ex("exchänge.example")}, exMalformed},
		{"exchange_empty", 403, [][2]string{cr(hintManifestURL), ex("")}, exMalformed},
		{"exchange_sent_twice", 403,
			[][2]string{cr(hintManifestURL), ex(hintExchange), ex("other-exchange.example")}, exMalformed},
		{"exchange_comma_list", 403,
			[][2]string{cr(hintManifestURL), ex(hintExchange + ", other-exchange.example")}, exMalformed},

		// Both malformed.
		{"both_malformed", 403,
			[][2]string{cr("https://exchange.example/v1/info"), ex("https://exchange.example")},
			hintExpectation{"", malformed, "", malformed}},
	}
	for i, r := range rows {
		got := expectationOf(ParseDiscoveryHint(r.Status, headerOf(r.Headers)))
		if got != r.Expected {
			t.Fatalf("%s: ParseDiscoveryHint = %+v, table says %+v; fix the table or the face", r.Name, got, r.Expected)
		}
		rows[i].Expected = got
	}
	return rows
}

func buildDiscoveryHintReconcileVectors(t *testing.T) []discoveryHintReconcileVector {
	t.Helper()
	both := [][2]string{cr(hintManifestURL), ex(hintExchange)}
	rows := []struct {
		name    string
		status  int
		headers [][2]string
		listed  []string
		want    HintAgreement
	}{
		{"listed", 403, both, []string{hintExchange}, HintListed},
		{"listed_among_several", 403, both, []string{"other-exchange.example", hintExchange}, HintListed},
		{"listed_case_folded", 403, [][2]string{cr(hintManifestURL), ex("EXCHANGE.example")}, []string{hintExchange}, HintListed},
		{"listed_default_port_folded", 403, [][2]string{cr(hintManifestURL), ex("exchange.example:443")}, []string{hintExchange}, HintListed},
		{"listed_with_same_port", 403, [][2]string{cr(hintManifestURL), ex("exchange.example:8081")}, []string{"exchange.example:8081"}, HintListed},

		// The header names an Exchange the manifest does not list: the manifest wins.
		{"unlisted", 403, both, []string{"other-exchange.example"}, HintUnlisted},
		{"unlisted_manifest_lists_none", 403, both, []string{}, HintUnlisted},
		{"unlisted_subdomain_is_another_party", 403, [][2]string{cr(hintManifestURL), ex("eu.exchange.example")}, []string{hintExchange}, HintUnlisted},
		{"unlisted_parent_is_another_party", 403, both, []string{"eu.exchange.example"}, HintUnlisted},
		{"unlisted_other_port", 403, [][2]string{cr(hintManifestURL), ex("exchange.example:8443")}, []string{hintExchange}, HintUnlisted},
		{"unlisted_port_80_not_folded", 403, [][2]string{cr(hintManifestURL), ex("exchange.example:80")}, []string{hintExchange}, HintUnlisted},
		{"unlisted_malformed_listing_matches_nothing", 403, both, []string{"https://exchange.example"}, HintUnlisted},

		// No usable Exchange in the hint: nothing to reconcile.
		{"no_exchange_header_missing", 403, [][2]string{cr(hintManifestURL)}, []string{hintExchange}, HintNoExchange},
		{"no_exchange_header_malformed", 403, [][2]string{cr(hintManifestURL), ex("https://exchange.example")}, []string{hintExchange}, HintNoExchange},
		{"no_exchange_not_a_403", 200, both, []string{hintExchange}, HintNoExchange},
	}
	out := make([]discoveryHintReconcileVector, 0, len(rows))
	for _, r := range rows {
		got := ReconcileDiscoveryHint(ParseDiscoveryHint(r.status, headerOf(r.headers)), r.listed)
		if got != r.want {
			t.Fatalf("%s: ReconcileDiscoveryHint = %s, table says %s; fix the table or the face", r.name, got, r.want)
		}
		out = append(out, discoveryHintReconcileVector{
			Name: r.name, Status: r.status, Headers: r.headers, Listed: r.listed, Agreement: got.String(),
		})
	}
	return out
}

// TestGenerateDiscoveryHintVectors emits testdata/discovery-hint-vectors.json.
func TestGenerateDiscoveryHintVectors(t *testing.T) {
	doc := map[string]any{
		"header_names": map[string]string{
			"content_rules": ContentRulesHeader,
			"exchange":      ExchangeHeader,
		},
		"parse":     buildDiscoveryHintParseVectors(t),
		"reconcile": buildDiscoveryHintReconcileVectors(t),
	}
	path := filepath.Join("testdata", "discovery-hint-vectors.json")
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
