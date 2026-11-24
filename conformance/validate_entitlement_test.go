package conformance

import (
	"slices"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// allValidationCases is every constraint probe, the set TestCELRuleCoverage holds
// against the custom CEL ids the proto declares.
func allValidationCases() []validationCase {
	return slices.Concat(licensingCases(), idempotencyCases(), errorDetailCases(), entitlementCases())
}

// entitlementCases probe the constraints of the profile 1.1 issuance messages.
func entitlementCases() []validationCase {
	return []validationCase{
		{
			"issue_entitlements_response pending valid",
			&forav1.IssueEntitlementsResponse{Status: forav1.IssuanceStatus_ISSUANCE_STATUS_PENDING},
			true,
			"",
		},
		{
			"issue_entitlements_response unspecified status rejected",
			&forav1.IssueEntitlementsResponse{},
			false,
			"issue_entitlements_response.status_specified",
		},
		{
			"subscription ending valid",
			&forav1.Subscription{Status: forav1.SubscriptionStatus_SUBSCRIPTION_STATUS_ENDING},
			true,
			"",
		},
		{
			"subscription unspecified status rejected",
			&forav1.Subscription{},
			false,
			"subscription.status_specified",
		},
	}
}

func TestEntitlementConstraints(t *testing.T) {
	runValidationCases(t, entitlementCases())
}
