// Package conformance holds machine checks that the doc-conformance denylist
// gate structurally cannot perform: it actually *evaluates* the protovalidate
// CEL constraints embedded in the proto, and validates the example payloads in
// the docs against the wire contract. A green run here means the constraints
// fire as written and the documented examples would survive ingestion.
package conformance

import (
	"strings"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// validationCase is one constraint probe. An invalid case names the rule id it
// expects to fire (wantRule): asserting *which* rule rejected the message — not
// merely that some rule did — is what catches a case that passes for the wrong
// reason (a renamed field, a mis-anchored regex tripping a different rule). A
// valid case leaves wantRule empty.
type validationCase struct {
	name      string
	msg       proto.Message
	wantValid bool
	wantRule  string // the protovalidate rule id expected when !wantValid
}

// runValidationCases evaluates each case and, for an invalid one, asserts the
// expected rule id is among the violations it produced.
func runValidationCases(t *testing.T, cases []validationCase) {
	t.Helper()
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.msg)
			if tc.wantValid {
				if tc.wantRule != "" {
					t.Fatalf("valid case must not declare a wantRule (got %q)", tc.wantRule)
				}
				if err != nil {
					t.Errorf("expected VALID, got error: %v", err)
				}
				return
			}
			if tc.wantRule == "" {
				t.Fatalf("invalid case must declare the rule id it expects to fire")
			}
			verr, ok := err.(*protovalidate.ValidationError)
			if !ok {
				t.Fatalf("expected INVALID (rule %q), but validation passed (err=%v)", tc.wantRule, err)
			}
			if !violationsContain(verr, tc.wantRule) {
				t.Errorf("expected a violation of rule %q, got %v — the case is rejected for a different reason than intended.", tc.wantRule, violationIDs(verr))
			}
		})
	}
}

func violationIDs(verr *protovalidate.ValidationError) []string {
	ids := make([]string, 0, len(verr.Violations))
	for _, v := range verr.Violations {
		ids = append(ids, v.Proto.GetRuleId())
	}
	return ids
}

func violationsContain(verr *protovalidate.ValidationError, id string) bool {
	for _, v := range verr.Violations {
		if v.Proto.GetRuleId() == id {
			return true
		}
	}
	return false
}

// TestProtovalidateConstraints exercises every CEL/standard constraint added by
// the licensing core against representative valid and invalid instances. Until
// this existed, a syntactically-valid-but-wrong CEL (mis-anchored regex,
// renamed field reference) shipped green because nothing in the toolchain ever
// evaluated the constraints — `buf lint` is style-only and `buf generate` just
// embeds the option bytes. This is the regression guard for that whole class.
func TestProtovalidateConstraints(t *testing.T) {
	runValidationCases(t, licensingCases())
}

func licensingCases() []validationCase {
	hex64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return []validationCase{
		// License.uri_digest — strong-hash structure only.
		{"uri_digest empty ok", &forav1.License{UriDigest: proto.String("")}, true, ""},
		{"uri_digest sha256 ok", &forav1.License{UriDigest: proto.String("sha256:" + hex64)}, true, ""},
		{"uri_digest md5 rejected", &forav1.License{UriDigest: proto.String("md5:" + hex64)}, false, "string.pattern"},
		{"uri_digest sha256 wrong length", &forav1.License{UriDigest: proto.String("sha256:dead")}, false, "string.pattern"},
		{"uri_digest sha256 non-hex", &forav1.License{UriDigest: proto.String("sha256:" + "g" + hex64[1:])}, false, "string.pattern"},

		// Pricing message-level CEL: PER_UNIT⇒unit set; FREE⇒rate 0.
		{"pricing per_unit with unit ok", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("tokens"), Currency: "USD", Rate: "0.05"}, true, ""},
		{"pricing per_unit without unit rejected", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Currency: "USD", Rate: "0.05"}, false, "pricing.per_unit.requires_unit"},
		{"pricing free zero rate ok", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FREE, Rate: "0"}, true, ""},
		{"pricing free nonzero rate rejected", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FREE, Rate: "1.0"}, false, "pricing.free.zero_rate"},

		// Pricing.unit format: empty / bare-dashed / vendor:namespaced.
		{"pricing unit bare ok", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("sq-km"), Rate: "1"}, true, ""},
		{"pricing unit vendor ok", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("acme:widgets"), Rate: "1"}, true, ""},
		{"pricing unit with space rejected", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Unit: proto.String("two words"), Rate: "1"}, false, "string.pattern"},

		// AcceptableRestriction.values charset + max_items.
		{"acceptable values ok", &forav1.AcceptableRestriction{Axis: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: []string{"ai-train", "ai-input"}}, true, ""},
		{"acceptable values space rejected", &forav1.AcceptableRestriction{Axis: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: []string{"ai train"}}, false, "string.pattern"},
		{"acceptable values too many rejected", &forav1.AcceptableRestriction{Axis: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Values: gen65()}, false, "repeated.max_items"},

		// Restriction.permitted/prohibited charset.
		{"restriction permitted ok", &forav1.Restriction{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}}, true, ""},
		{"restriction permitted control-char rejected", &forav1.Restriction{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"bad\ttoken"}}, false, "string.pattern"},
		{"restriction prohibited ok", &forav1.Restriction{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Prohibited: []string{"ai-train"}}, true, ""},
		{"restriction prohibited space rejected", &forav1.Restriction{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Prohibited: []string{"ai train"}}, false, "string.pattern"},

		// Quota.metric format — bare-dashed or vendor:namespaced; empty rejected.
		// window set so the only variable under test is metric.
		{"quota metric bare ok", &forav1.Quota{Metric: "display-words", Limit: 1, Window: forav1.QuotaWindow_QUOTA_WINDOW_DAILY}, true, ""},
		{"quota metric vendor ok", &forav1.Quota{Metric: "acme:frames", Limit: 1, Window: forav1.QuotaWindow_QUOTA_WINDOW_DAILY}, true, ""},
		{"quota metric empty rejected", &forav1.Quota{Metric: "", Limit: 1, Window: forav1.QuotaWindow_QUOTA_WINDOW_DAILY}, false, "string.pattern"},
		{"quota metric space rejected", &forav1.Quota{Metric: "two words", Limit: 1, Window: forav1.QuotaWindow_QUOTA_WINDOW_DAILY}, false, "string.pattern"},

		// License.uri present requires uri_digest (any semantics).
		{"license no uri ok", &forav1.License{Id: proto.String("CC-BY-4.0")}, true, ""},
		{"license uri with digest ok", &forav1.License{Uri: proto.String("https://x.example/lic"), UriDigest: proto.String("sha256:" + hex64)}, true, ""},
		{"license uri without digest rejected", &forav1.License{Uri: proto.String("https://x.example/lic")}, false, "license.digest_required_with_uri"},

		// LicenseTerm presence invariants (pricing required; REFERENCE_ONLY needs license.uri).
		{"term enumerated with pricing ok", &forav1.LicenseTerm{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: freePricing()}, true, ""},
		{"term missing pricing rejected", &forav1.LicenseTerm{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED}, false, "required"},
		{"term reference_only with license uri ok", &forav1.LicenseTerm{Semantics: forav1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, Pricing: freePricing(), License: &forav1.License{Uri: proto.String("https://x.example/lic"), UriDigest: proto.String("sha256:" + hex64)}}, true, ""},
		{"term reference_only without license uri rejected", &forav1.LicenseTerm{Semantics: forav1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, Pricing: freePricing()}, false, "license_term.reference_only.requires_uri"},

		// license-term coherence rules.
		{"restriction disjoint ok", &forav1.Restriction{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}, Prohibited: []string{"ai-train"}}, true, ""},
		{"restriction overlap rejected", &forav1.Restriction{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-input"}, Prohibited: []string{"ai-input"}}, false, "restriction.permitted_prohibited_disjoint"},
		{"term one restriction per kind ok", &forav1.LicenseTerm{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: freePricing(), Restrictions: []*forav1.Restriction{{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION}, {Kind: forav1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY}}}, true, ""},
		{"term duplicate restriction kind rejected", &forav1.LicenseTerm{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: freePricing(), Restrictions: []*forav1.Restriction{{Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION}, {Kind: forav1.RestrictionKind_RESTRICTION_KIND_FUNCTION}}}, false, "license_term.one_restriction_per_kind"},
		{"quota limit ok", &forav1.Quota{Metric: "accesses", Limit: 1, Window: forav1.QuotaWindow_QUOTA_WINDOW_DAILY}, true, ""},
		{"quota limit zero rejected", &forav1.Quota{Metric: "accesses", Limit: 0, Window: forav1.QuotaWindow_QUOTA_WINDOW_DAILY}, false, "int64.gte"},
		{"obligation share_alike with spdx id ok", &forav1.Obligation{Kind: forav1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: forav1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, ScopeLicense: &forav1.License{Id: proto.String("CC-BY-SA-4.0")}}, true, ""},
		{"obligation share_alike without scope_license rejected", &forav1.Obligation{Kind: forav1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: forav1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}, false, "obligation.share_alike.requires_scope_license"},
		{"obligation share_alike scope_license uri+digest ok", &forav1.Obligation{Kind: forav1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: forav1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, ScopeLicense: &forav1.License{Uri: proto.String("https://creativecommons.org/licenses/by-sa/4.0/"), UriDigest: proto.String("sha256:" + hex64)}}, true, ""},
		{"obligation share_alike scope_license uri without digest rejected", &forav1.Obligation{Kind: forav1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: forav1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE, ScopeLicense: &forav1.License{Uri: proto.String("https://creativecommons.org/licenses/by-sa/4.0/")}}, false, "license.digest_required_with_uri"},

		// Required-enum discriminators — UNSPECIFIED (zero) is never a valid value.
		// These guard the gap where the conditional coherence CELs above are
		// vacuously satisfied by an unset discriminator.
		{"term semantics unspecified rejected", &forav1.LicenseTerm{Pricing: freePricing()}, false, "enum.not_in"},
		{"pricing model unspecified rejected", &forav1.Pricing{Rate: "0"}, false, "enum.not_in"},
		{"restriction kind unspecified rejected", &forav1.Restriction{Permitted: []string{"ai-input"}}, false, "enum.not_in"},
		{"obligation kind unspecified rejected", &forav1.Obligation{Trigger: forav1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}, false, "enum.not_in"},
		{"quota window unspecified rejected", &forav1.Quota{Metric: "accesses", Limit: 1}, false, "enum.not_in"},
		{"obligation trigger unspecified rejected", &forav1.Obligation{Kind: forav1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION}, false, "enum.not_in"},

		// Discriminator + format CELs on messages OUTSIDE the licensing core. The
		// rules are identical in shape to the ones above; covering them here keeps
		// TestCELRuleCoverage's completeness assertion green for the whole proto,
		// not just the licensing subtree.
		{"authorized_exchange relationship set ok", &forav1.AuthorizedExchange{Domain: exampleExchange, Relationship: forav1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT}, true, ""},
		{"authorized_exchange relationship unspecified rejected", &forav1.AuthorizedExchange{Domain: exampleExchange}, false, "enum.not_in"},
		{"requester type set ok", &forav1.Requester{Domain: "agent.example", Type: forav1.RequesterType_REQUESTER_TYPE_AGENT}, true, ""},
		{"requester type unspecified rejected", &forav1.Requester{Domain: "agent.example"}, false, "enum.not_in"},
		{"resource_identity mutability set ok", &forav1.ResourceIdentity{ResourceMutability: forav1.ResourceMutability_RESOURCE_MUTABILITY_STATIC}, true, ""},
		{"resource_identity mutability unspecified rejected", &forav1.ResourceIdentity{}, false, "enum.not_in"},
		{"well_known_manifest role set ok", &forav1.WellKnownManifest{Role: forav1.Role_ROLE_AGENT}, true, ""},
		{"well_known_manifest role unspecified rejected", &forav1.WellKnownManifest{}, false, "enum.not_in"},
		// A digest pins the document at terms_uri, so publishing one without the
		// address it pins leaves nothing to check the bytes against.
		{"well_known_manifest terms_digest without terms_uri rejected", &forav1.WellKnownManifest{
			Role:        forav1.Role_ROLE_EXCHANGE,
			TermsDigest: proto.String("sha256:" + strings.Repeat("ab", 32)),
		}, false, "well_known_manifest.terms_digest_requires_terms_uri"},
		// The read-side mirror. The digest states what an ACCOUNT accepted, so it
		// cannot travel without the handle it hangs on: a reader taking it from an
		// accountless response would hold an acceptance for an account that does
		// not exist.
		{"get_account_status_response terms_digest without billing_ref rejected", &forav1.GetAccountStatusResponse{
			TermsDigest: proto.String("sha256:" + strings.Repeat("ab", 32)),
		}, false, "get_account_status_response.terms_digest_requires_billing_ref"},
		{"get_account_status_response terms_digest with billing_ref ok", &forav1.GetAccountStatusResponse{
			BillingRef:  "acct-1",
			TermsDigest: proto.String("sha256:" + strings.Repeat("ab", 32)),
		}, true, ""},
		{"well_known_manifest terms_digest with terms_uri ok", &forav1.WellKnownManifest{
			Role:        forav1.Role_ROLE_EXCHANGE,
			TermsUri:    proto.String("https://exchange.example/terms"),
			TermsDigest: proto.String("sha256:" + strings.Repeat("ab", 32)),
		}, true, ""},
		// field_errors is member-level detail for the schema refusal; any other
		// reason carrying it is detail that does not apply to the refusal.
		{"registration_failure field_errors with stale-terms reason rejected", &forav1.RegistrationFailure{
			Reason:      forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE,
			FieldErrors: []*forav1.RegistrationFieldError{{Path: "/vat_id", Error: "required"}},
		}, false, "registration_failure.field_errors_scoped_to_invalid_data"},
		{"registration_failure field_errors with invalid-data reason ok", &forav1.RegistrationFailure{
			Reason:      forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
			FieldErrors: []*forav1.RegistrationFieldError{{Path: "/vat_id", Error: "required"}},
		}, true, ""},
		{"registration_failure stale-terms without field_errors ok", &forav1.RegistrationFailure{
			Reason: forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE,
		}, true, ""},
		{"well_known_manifest terms_uri without digest ok", &forav1.WellKnownManifest{
			Role:     forav1.Role_ROLE_EXCHANGE,
			TermsUri: proto.String("https://exchange.example/terms"),
		}, true, ""},
		{"dispute_request reason set ok", &forav1.DisputeRequest{IdempotencyKey: "idem-dr-x", Exchange: exampleExchange, Reason: forav1.DisputeReason_DISPUTE_REASON_CONTENT_MISMATCH}, true, ""},
		{"dispute_request reason unspecified rejected", &forav1.DisputeRequest{IdempotencyKey: "idem-dr-x", Exchange: exampleExchange}, false, "enum.not_in"},
		{"usage consumed_unit empty ok", &forav1.Usage{}, true, ""},
		{"usage consumed_unit bare ok", &forav1.Usage{ConsumedUnit: proto.String("tokens")}, true, ""},
		{"usage consumed_unit space rejected", &forav1.Usage{ConsumedUnit: proto.String("two words")}, false, "string.pattern"},
	}
}

// TestIdempotencyKeyRequired asserts the state-mutating requests require a
// non-empty idempotency_key — the dedup guarantee has no teeth without it. The
// proto declares the contract ahead of full enforcement; this is the guard that
// the required-key constraint actually fires across every SDK.
func TestIdempotencyKeyRequired(t *testing.T) {
	runValidationCases(t, idempotencyCases())
}

func idempotencyCases() []validationCase {
	return []validationCase{
		{"transaction empty key rejected", &forav1.TransactionRequest{IdempotencyKey: "", Items: []*forav1.TransactionItem{{Offer: &forav1.Offer{OfferId: "of_1", Exchange: exampleExchange, Pricing: freePricing()}}}}, false, "string.min_len"},
		{"transaction key ok", &forav1.TransactionRequest{IdempotencyKey: "idem-tx-1", Items: []*forav1.TransactionItem{{Offer: &forav1.Offer{OfferId: "of_1", Exchange: exampleExchange, Pricing: freePricing()}}}}, true, ""},
		{"transaction empty items rejected", &forav1.TransactionRequest{IdempotencyKey: "idem-tx-empty"}, false, "repeated.min_items"},
		{"usage report empty key rejected", &forav1.UsageReport{IdempotencyKey: "", Exchange: exampleExchange}, false, "string.min_len"},
		{"usage report key ok", &forav1.UsageReport{IdempotencyKey: "idem-ur-1", Exchange: exampleExchange}, true, ""},
		{"dispute empty key rejected", &forav1.DisputeRequest{IdempotencyKey: "", Exchange: exampleExchange, Reason: forav1.DisputeReason_DISPUTE_REASON_CONTENT_MISMATCH}, false, "string.min_len"},
		{"dispute key ok", &forav1.DisputeRequest{IdempotencyKey: "idem-dr-1", Exchange: exampleExchange, Reason: forav1.DisputeReason_DISPUTE_REASON_CONTENT_MISMATCH}, true, ""},
	}
}

// exampleExchange is a valid recipient host for fixtures whose subject is some
// OTHER constraint. Every addressed request now carries `exchange`, so a case
// that omits it fails on the recipient rule instead of the rule it was written
// to exercise.
const exampleExchange = "exchange.example"

func freePricing() *forav1.Pricing {
	return &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FREE, Rate: "0"}
}

func gen65() []string {
	s := make([]string, 65)
	for i := range s {
		s[i] = "tok"
	}
	return s
}

// TestErrorDetailConstraints exercises the unified error model: every per-domain
// detail's reason enum must be a defined, non-UNSPECIFIED value (defined_only +
// not_in:[0]), and the ErrorDetail wrapper validates the nested detail. This is
// the regression guard that errors are read as a typed proto reason — never an
// UNSPECIFIED placeholder or an out-of-range int — across every SDK language.
func TestErrorDetailConstraints(t *testing.T) {
	runValidationCases(t, errorDetailCases())
}

func errorDetailCases() []validationCase {
	return []validationCase{
		// TransactionDenial — reuses DenialReason, including the entitlement family.
		{"transaction_denial valid", &forav1.TransactionDenial{Reason: forav1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE}, true, ""},
		{"transaction_denial entitlement valid", &forav1.TransactionDenial{Reason: forav1.DenialReason_DENIAL_REASON_ENTITLEMENT_NOT_GRANTED}, true, ""},
		{"transaction_denial unspecified rejected", &forav1.TransactionDenial{Reason: forav1.DenialReason_DENIAL_REASON_UNSPECIFIED}, false, "enum.not_in"},
		{"transaction_denial undefined int rejected", &forav1.TransactionDenial{Reason: forav1.DenialReason(9999)}, false, "enum.defined_only"},

		// One representative valid + zero-rejected case per remaining detail.
		{"catalog_rejection valid", &forav1.CatalogRejection{Reason: forav1.CatalogRejectionReason_CATALOG_REJECTION_REASON_TENANT_MISMATCH}, true, ""},
		{"catalog_rejection unspecified rejected", &forav1.CatalogRejection{Reason: forav1.CatalogRejectionReason_CATALOG_REJECTION_REASON_UNSPECIFIED}, false, "enum.not_in"},
		{"registration_failure valid", &forav1.RegistrationFailure{Reason: forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_KEY}, true, ""},
		{"registration_failure unspecified rejected", &forav1.RegistrationFailure{Reason: forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_UNSPECIFIED}, false, "enum.not_in"},
		// Schema-enforcement refusal: the reason travels with the offending
		// registration_data members. The per-field length bounds and the
		// max_items boundary are generated corpus coverage
		// (RegistrationFieldError/*, RegistrationFailure/field_errors/too_many);
		// what the generator cannot express is a MULTI-member refusal, and that
		// the empty path — a legal RFC 6901 pointer to registration_data itself,
		// for the whole-object failure that belongs to no single member — is
		// accepted rather than read as an unset field.
		{"registration_failure invalid data with field errors valid", &forav1.RegistrationFailure{
			Reason: forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
			FieldErrors: []*forav1.RegistrationFieldError{
				{Path: "/vat_id", Error: "must match ^[A-Z]{2}[0-9]+$"},
				{Path: "/address/postal_code", Error: "required"},
				{Path: "", Error: "matched 2 branches of oneOf, exactly 1 required"},
			},
		}, true, ""},
		{"dispute_failure valid", &forav1.DisputeFailure{Reason: forav1.DisputeFailureReason_DISPUTE_FAILURE_REASON_REPORT_NOT_FILED}, true, ""},
		{"dispute_failure unspecified rejected", &forav1.DisputeFailure{Reason: forav1.DisputeFailureReason_DISPUTE_FAILURE_REASON_UNSPECIFIED}, false, "enum.not_in"},
		{"domain_verification_failure valid", &forav1.DomainVerificationFailure{Reason: forav1.DomainVerificationFailureReason_DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_MISMATCH}, true, ""},
		{"domain_verification_failure unspecified rejected", &forav1.DomainVerificationFailure{Reason: forav1.DomainVerificationFailureReason_DOMAIN_VERIFICATION_FAILURE_REASON_UNSPECIFIED}, false, "enum.not_in"},
		{"retrieval_auth_failure valid", &forav1.RetrievalAuthFailure{Reason: forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH}, true, ""},
		{"retrieval_auth_failure unspecified rejected", &forav1.RetrievalAuthFailure{Reason: forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_UNSPECIFIED}, false, "enum.not_in"},
		{"usage_report_rejection valid", &forav1.UsageReportRejection{Reason: forav1.UsageReportRejectionReason_USAGE_REPORT_REJECTION_REASON_DUPLICATE}, true, ""},
		{"usage_report_rejection unspecified rejected", &forav1.UsageReportRejection{Reason: forav1.UsageReportRejectionReason_USAGE_REPORT_REJECTION_REASON_UNSPECIFIED}, false, "enum.not_in"},

		// ErrorDetail wrapper: carries a generic class (no typed reason) or a valid
		// typed detail; a nested invalid reason fails through the wrapper.
		{"error_detail generic class only ok", &forav1.ErrorDetail{Message: "internal", Domain: "fora.v1.ExchangeService"}, true, ""},
		{"error_detail with valid detail ok", &forav1.ErrorDetail{Reason: &forav1.ErrorDetail_TransactionDenial{TransactionDenial: &forav1.TransactionDenial{Reason: forav1.DenialReason_DENIAL_REASON_RATE_LIMITED}}}, true, ""},
		{"error_detail with unspecified nested reason rejected", &forav1.ErrorDetail{Reason: &forav1.ErrorDetail_TransactionDenial{TransactionDenial: &forav1.TransactionDenial{Reason: forav1.DenialReason_DENIAL_REASON_UNSPECIFIED}}}, false, "enum.not_in"},
	}
}

// standardRuleIDs are the buf-provided (non-custom-CEL) rule ids the corpus
// legitimately expects. Completeness (below) is enforced only over the custom
// CEL rules authored in this repo — the standard rules are buf's, not ours — but
// listing them lets the integrity check reject a mistyped wantRule that is
// neither a real custom CEL id nor a known standard rule.
var standardRuleIDs = map[string]bool{
	"string.pattern":     true,
	"required":           true,
	"repeated.max_items": true,
	"repeated.min_items": true,
	"int64.gte":          true,
	"string.min_len":     true,
	"enum.not_in":        true,
	"enum.defined_only":  true,
}

// TestCELRuleCoverage is INV-5: every custom CEL rule id declared in the proto
// must be exercised by at least one invalid case that fails *because of that
// rule*, and every rule a case claims must be a real rule (no typos, no stale
// ids). Coverage is derived from the descriptor, not a hand-kept list, so a
// newly-added CEL is REQUIRED to have a triggering test the moment it exists —
// closing the gap where a rule could ship untested and green. It composes with
// runValidationCases: that proves each claimed rule actually fires; this proves
// every declared rule is claimed. Together: every declared CEL actually fires.
func TestCELRuleCoverage(t *testing.T) {
	declared := map[string]bool{}
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if mr, err := protovalidate.ResolveMessageRules(md); err == nil && mr != nil {
			for _, r := range mr.GetCel() {
				declared[r.GetId()] = true
			}
		}
		for j := 0; j < md.Fields().Len(); j++ {
			if fr, err := protovalidate.ResolveFieldRules(md.Fields().Get(j)); err == nil && fr != nil {
				for _, r := range fr.GetCel() {
					declared[r.GetId()] = true
				}
			}
		}
	})
	if len(declared) == 0 {
		t.Fatal("no custom CEL ids found in the descriptor — the resolver path drifted; INV-5 would be vacuous.")
	}

	var all []validationCase
	all = append(all, licensingCases()...)
	all = append(all, idempotencyCases()...)
	all = append(all, errorDetailCases()...)

	claimed := map[string]bool{}
	for _, c := range all {
		if c.wantValid {
			continue
		}
		claimed[c.wantRule] = true
		// Integrity: a claimed rule must be a real rule — a declared custom CEL or a
		// known standard rule — so a typo cannot masquerade as coverage.
		if !declared[c.wantRule] && !standardRuleIDs[c.wantRule] {
			t.Errorf("case %q claims rule %q, which is neither a declared custom CEL id nor a known standard rule (typo, or a new standard rule to add to standardRuleIDs).", c.name, c.wantRule)
		}
	}

	// Completeness: every declared custom CEL id must be claimed by some case.
	for id := range declared {
		if !claimed[id] {
			t.Errorf("custom CEL rule %q is declared in the proto but no invalid case exercises it — add a case whose wantRule is %q.", id, id)
		}
	}
}
