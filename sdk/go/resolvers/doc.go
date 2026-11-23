// Package resolvers is the network-fetching L2 tier of the FORA SDK: the key,
// endpoint and offer-key resolvers, the readers of published documents and of
// the registration requirements, the content fetcher, and the SSRF-guarded HTTP
// client. A fetch whose host comes from a request goes through the guarded
// client by default; the well-known JWKS resolver, whose URL the operator
// chooses, defaults to http.DefaultClient. The package composes the L1 helpers
// package, never the reverse.
package resolvers
