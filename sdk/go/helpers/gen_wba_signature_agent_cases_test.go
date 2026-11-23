package helpers

// The -01 Signature-Agent cases the corpus emitter signs and records: what a
// verifier accepts, the members it ignores, and the values it refuses. Each case
// states the refusal its author intends; the emitter takes the outcome from the
// REAL Go verifier and refuses to write a case where the two disagree.

import "github.com/FORA-Protocol/protocol/sdk/go/internal/wbadir"

// wbaMember is the one-member dictionary sig1="<v>".
func wbaMember(v string) string { return `sig1="` + v + `"` }

// The members the cases share: the signer's well-known URL, and another signer's
// member a request may carry beside it.
var (
	wbaWellKnownMember = wbaMember(wbaWellKnown)
	wbaOtherMember     = `other="https://other.example` + wbadir.Path + `"`
)

// wbaCases is every verifier case, in corpus order.
func wbaCases() []wbaCase {
	return append(append(wbaAcceptedCases(), wbaIgnoredCases()...), wbaRefusedCases()...)
}

func wbaAcceptedCases() []wbaCase {
	return []wbaCase{
		// Accepted: each names the well-known key directory of agent.example (or of
		// relay.example:8443), whichever form carries it.
		{name: "well_known_url", lines: []string{wbaWellKnownMember}, sdk: wbaWellKnown},
		{name: "bare_origin_completed", lines: []string{wbaMember(negAgent)}, sdk: negAgent},
		{
			name:  "well_known_url_with_port",
			lines: []string{wbaMember("https://relay.example:8443" + wbadir.Path)},
			edit:  noEdit,
		},
		{
			name:  "bare_origin_with_port_completed",
			lines: []string{wbaMember("https://relay.example:8443")},
			edit:  noEdit,
		},
		{name: "legacy_string_well_known_url", lines: []string{`"` + wbaWellKnown + `"`}, edit: legacyCovered},
		{name: "legacy_string_bare_origin_completed", lines: []string{`"` + negAgent + `"`}, edit: legacyCovered},
		{
			name:  "member_key_differs_from_label",
			lines: []string{`agent="` + wbaWellKnown + `"`},
			edit: func(p *sigParams) {
				p.Covered = append(plainComponents(requiredCoveredComponents...), signatureAgentComponent("agent"))
			},
		},
		{
			name:  "repeated_field_lines_member_on_first",
			lines: []string{wbaWellKnownMember, wbaOtherMember},
			edit:  noEdit,
		},
		{
			name:  "repeated_field_lines_member_on_second",
			lines: []string{wbaOtherMember, wbaWellKnownMember},
			edit:  noEdit,
		},
		{name: "escaped_quote_in_another_member", lines: []string{`x="a\"b", ` + wbaWellKnownMember}, edit: noEdit},
		{
			name:  "ignored_member_beside_the_signers",
			lines: []string{wbaOtherMember + `;type=directory, ` + wbaWellKnownMember},
			edit:  noEdit,
		},
	}
}

func wbaIgnoredCases() []wbaCase {
	return []wbaCase{
		// A member that carries any parameter is ignored, and the signature covering
		// it names no directory.
		{
			name:    "member_with_parameter",
			lines:   []string{wbaWellKnownMember + `;type=directory`},
			edit:    noEdit,
			refusal: wbaRefusalIgnored,
		},
		{
			name:       "member_type_directory_string",
			lines:      []string{wbaMember(negAgent) + `;type="directory"`},
			edit:       noEdit,
			refusal:    wbaRefusalIgnored,
			supersedes: "verify-request-accept-vectors.json#accept_member_type_directory",
		},
		{
			name:       "member_type_directory_token",
			lines:      []string{wbaMember(negAgent) + `;type=directory`},
			edit:       noEdit,
			refusal:    wbaRefusalIgnored,
			supersedes: "verify-request-accept-vectors.json#accept_member_type_directory_token",
		},
		{
			name:    "member_with_other_parameter",
			lines:   []string{wbaWellKnownMember + `;x=1`},
			edit:    noEdit,
			refusal: wbaRefusalIgnored,
		},
		{
			name:    "legacy_string_with_parameter",
			lines:   []string{`"` + wbaWellKnown + `";type=directory`},
			edit:    legacyCovered,
			refusal: wbaRefusalIgnored,
		},
		{
			name:    "repeated_field_lines_member_with_parameter",
			lines:   []string{wbaOtherMember, wbaWellKnownMember + `;type=directory`},
			edit:    noEdit,
			refusal: wbaRefusalIgnored,
		},
	}
}

func wbaRefusedCases() []wbaCase {
	return []wbaCase{
		// Any other URL is refused with a typed reason.
		{
			name:    "other_path",
			lines:   []string{wbaMember(negAgent + "/jwks.json")},
			edit:    noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name:    "origin_with_trailing_slash",
			lines:   []string{wbaMember(negAgent + "/")},
			edit:    noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name: "well_known_path_with_trailing_slash", lines: []string{wbaMember(wbaWellKnown + "/")}, edit: noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name:    "well_known_path_in_another_case",
			lines:   []string{wbaMember(negAgent + "/.well-known/HTTP-Message-Signatures-Directory")},
			edit:    noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name:    "query",
			lines:   []string{wbaMember(wbaWellKnown + "?v=1")},
			edit:    noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name:    "bare_origin_with_query",
			lines:   []string{wbaMember(negAgent + "?v=1")},
			edit:    noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name:    "fragment",
			lines:   []string{wbaMember(wbaWellKnown + "#k")},
			edit:    noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name: "escaped_quote_in_the_covered_value", lines: []string{`sig1="` + wbaWellKnown + `\"x"`}, edit: noEdit,
			refusal: wbaRefusalNotKeyDirectory,
		},
		{
			name: "http_well_known_url", lines: []string{wbaMember("http://agent.example" + wbadir.Path)}, edit: noEdit,
			refusal: wbaRefusalNotHTTPSOrigin,
		},
		{
			name:    "http_bare_origin",
			lines:   []string{wbaMember("http://agent.example")},
			edit:    noEdit,
			refusal: wbaRefusalNotHTTPSOrigin,
		},
		{
			name: "credentials", lines: []string{wbaMember("https://user@agent.example" + wbadir.Path)}, edit: noEdit,
			refusal: wbaRefusalNotHTTPSOrigin,
		},
		{
			name: "uppercase_host", lines: []string{wbaMember("https://Agent.example" + wbadir.Path)}, edit: noEdit,
			refusal: wbaRefusalNotHTTPSOrigin,
		},
		{name: "member_not_a_string", lines: []string{`sig1=agent`}, edit: noEdit, refusal: wbaRefusalForm},
	}
}
