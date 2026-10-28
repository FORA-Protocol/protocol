package requestflows

import "testing"

// TestScaffoldCompiles exists so `go test ./...` builds this package; the
// compile itself is the check.
func TestScaffoldCompiles(t *testing.T) { _ = (&ExchangeHandler{}).DiscoverResources }
