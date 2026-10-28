// Package requestflows compiles the DiscoverResources handler example of the
// Exchange request-flows page against typed stubs, so a variable used before
// it is declared, a name that is never defined or a wrong SDK call fails
// `go build` instead of sitting in the documentation. handler.go is extracted
// from the page by conformance/docgo_test.go; this file is the scaffold the
// example needs and the only hand-written part.
package requestflows

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// ExchangeHandler is the handler the example is a method of. Every field is
// an interface the example calls; none has an implementation here.
type ExchangeHandler struct {
	brokers interface {
		Admits(signatureAgent string) bool
	}
	accounts interface {
		ForDirectory(ctx context.Context, directory string) (*Account, error)
	}
	tenants interface {
		ResolveFromURIs(uris []string) (*TenantConfig, error)
	}
	subscriptions interface {
		RecordsForTenant(ctx context.Context, tenantID string) []SubscriptionRecord
	}
	journal interface {
		DelegationRefused(ctx context.Context, recordID string, err error)
	}
	catalog interface {
		FindOffers(ctx context.Context, tenantID string, uris, statedScopes []string, grants map[string]*helpers.VerifiedDelegation) ([]*forav1.Offer, error)
	}
	billing   Billing
	reporting interface {
		GetPolicy(tenantID string) *forav1.ReportingObligation
	}
	offerSigner interface {
		Sign(offer *forav1.Offer) (string, error)
	}
	clock          interface{ Now() time.Time }
	exchangeDomain string
}

// Billing answers subscription questions for the account the query resolved.
type Billing interface {
	CheckSubscription(ctx context.Context, billingRef, tenantID string) (*SubscriptionStatus, error)
	SubscriptionQuota(ctx context.Context, subscriptionID, tenantID string) []*forav1.SubscriptionQuotaInfo
}

// Account is the registered account a key directory resolves to.
type Account struct{ BillingRef string }

// TenantConfig is the publisher tenant the queried URIs belong to. Identity is
// the Exchange's own recipient identity, the value a delegation's aud must name.
type TenantConfig struct{ ID, Identity string }

// SubscriptionRecord is one subscription with the root issuer keys it trusts.
type SubscriptionRecord struct {
	ID             string
	TrustedIssuers []helpers.TrustedIssuer
}

// SubscriptionStatus is the billing view of one subscription.
type SubscriptionStatus struct {
	Active         bool
	SubscriptionID string
}

func validate(msg *forav1.ResourceQuery) error { return helpers.Validate(msg) }

// offerMatchesURI reports whether an offer answers the queried URI.
func offerMatchesURI(offer *forav1.Offer, uri string) bool {
	return offer.GetIdentity().GetCanonicalUrl() == uri
}

// newOpaqueID mints an opaque offer id; the example only needs it to be fresh.
func newOpaqueID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
