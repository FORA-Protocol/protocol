// Public surface of the FORA SDK resolver faces (ADR-020 §4), the Node entry (package
// export "./resolvers"). These are the FIRST IO in the TS SDK, so they live OUTSIDE the
// IO-free core/src tree (exported via package.json `exports`) to keep the
// transport-neutrality invariant on core green. Four faces port the Go oracle: a static
// named map, a well-known JWKS key resolver, a host-keyed well-known endpoint resolver,
// and the WBA identity-directory resolver + revocation poller. The typed error classes
// preserve the oracle's errors.Is-DISTINCT fail-closed taxonomy.
//
// This entry is the edge-safe one (edge.ts) with each fetching face's transport
// defaulted (node-defaults.ts), plus the Node-only transports themselves: the
// SSRF-guarded undici client and its env-driven factory. An edge runtime imports
// "./resolvers/edge" instead, and passes its own fetch.

export * from "./edge.ts";
export {
	createWBAKeyResolver,
	createWBAOfferDirectoryFetch,
	createWellKnownEndpointResolver,
	createWellKnownKeyResolver,
	createWellKnownRequirementsReader,
	type EndpointOptions,
	type ReadDocumentOptions,
	readLicenseDocument,
	readManifest,
	readRevocationList,
	readWBADirectory,
	type WBAKeyResolverOptions,
	type WBAOfferDirectoryFetchOptions,
	type WellKnownOptions,
	type WellKnownRequirementsOptions,
} from "./node-defaults.ts";
export { guardedFetchFromEnv, SsrfBlockedError, ssrfGuard } from "./http.ts";
