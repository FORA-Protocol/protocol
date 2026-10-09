// The edge-safe entry of the FORA SDK resolver faces (package export
// "./resolvers/edge"): every resolver and document reader, with nothing Node-only in its
// import graph — no undici, no node: module, no Buffer or process. It is the entry a
// Cloudflare Workers, Fastly Compute or Deno runtime imports.
//
// Every fetching face takes the transport as a REQUIRED `fetch` option (the FetchLike
// shape: the runtime's own fetch, or a wrapper around it). There is no default: the
// SSRF-guarded default transport the Node entry ("./resolvers") supplies dials through
// undici with DNS pinning, which an edge runtime does not have.
//
// The read bounds itself whatever fetch it is given (fetch.ts): a body is capped at 1 MiB,
// the whole read ends at 30 seconds, and the read follows redirects itself — at most five,
// never out of http(s), never from https down to http, never with credentials, and never
// for a key directory. What stays with the caller is the address: an edge runtime that
// fetches an address another party chose (a Signature-Agent directory, an Exchange
// domain) owns the equivalent of the SSRF guard. blockedAddress is exported for it, and
// allowedScheme, the scheme allowlist (http and https) that guard applies; it is not an
// https-only rule.
// tests/edge-imports.guard.test.ts walks this module's import graph and fails on any
// Node-only import, and tsconfig.workers.json typechecks it against the Workers types.

export {
	type Document,
	type KeyRevocationList,
	type License,
	type LicenseDocument,
	MANIFEST_MEDIA_TYPE,
	type ReadDocumentOptions,
	readLicenseDocument,
	readManifest,
	readRevocationList,
	readWBADirectory,
	WBA_DIRECTORY_MEDIA_TYPE,
	type WBAFile,
	type WellKnownManifest,
} from "./documents.ts";
export {
	DigestMismatch,
	DirectoryResponseUnsigned,
	DirectoryUnavailable,
	EndpointRefused,
	ExchangeNotPermitted,
	KeyExpired,
	KeyRevoked,
	ManifestNotExchange,
	ManifestUnusable,
	ManifestVersionRefused,
	MediaTypeRefused,
	NoEndpoint,
	ResolverError,
	RevocationUnevaluated,
	UnknownKey,
} from "./errors.ts";
export type { FetchInit, FetchLike, FetchResponse } from "./fetch.ts";
export {
	type CachedOfferKeyResolver,
	type CachedOfferKeyResolverOptions,
	clampOfferKeyExpiry,
	createCachedOfferKeyResolver,
	createWBAOfferDirectoryFetch,
	type OfferDirectoryFetch,
	type WBAOfferDirectoryFetchOptions,
} from "./offer-key-cache.ts";
export {
	createWellKnownRequirementsReader,
	type RegistrationRequirements,
	type WellKnownRequirementsOptions,
	type WellKnownRequirementsReader,
} from "./registration-requirements.ts";
export { StrictViolation } from "../src/strict-core.ts";
export { allowedScheme, blockedAddress } from "./ssrf.ts";
export { createStaticKeyResolver, type StaticKeyResolver } from "./static.ts";
export {
	activeEd25519Key,
	activeEd25519KeyScreened,
	activeEd25519KeyWithExpiry,
	activeEd25519KeyWithExpiryScreened,
	createWBAKeyResolver,
	WBA_DIRECTORY_PATH,
	type WBAKeyResolver,
	type WBAKeyResolverOptions,
	wbaDirectoryURL,
} from "./wba.ts";
export {
	type EndpointOptions,
	createWellKnownEndpointResolver,
	createWellKnownKeyResolver,
	type WellKnownEndpointResolver,
	type WellKnownKeyResolver,
	type WellKnownOptions,
} from "./wellknown.ts";
