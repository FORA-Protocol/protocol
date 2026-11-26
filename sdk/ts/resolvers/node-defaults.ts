// The Node entry's resolver factories and document readers: the edge-safe ones, each with
// the transport defaulted the way it always has been. The edge-safe modules take `fetch`
// as a required option and import nothing Node-only; this module is the one place a
// default transport is chosen, so the Node-only undici client stays out of the edge
// entry's import graph.
//
// Which default a resolver takes follows its URL's PROVENANCE (see defaultFetch in
// http.ts): a fixed, operator-chosen address takes the plain transport, a host another
// party named takes a guarded one.

import * as documents from "./documents.ts";
import type { FetchLike } from "./fetch.ts";
import { createGuardedFetch, defaultFetch, guardedFetch } from "./http.ts";
import * as offerKeyCache from "./offer-key-cache.ts";
import * as requirements from "./registration-requirements.ts";
import * as wba from "./wba.ts";
import * as wellknown from "./wellknown.ts";

/** How a document reader dials. `fetch` defaults to createGuardedFetch(), built for
 * the call. */
export type ReadDocumentOptions = Omit<documents.ReadDocumentOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the WBA resolver. `fetch` defaults to the SSRF-guarded transport: the
 * directory host comes from the request-supplied Signature-Agent and is fetched
 * pre-auth (matches the Go oracle). */
export type WBAKeyResolverOptions = Omit<wba.WBAKeyResolverOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the well-known key resolver. `fetch` defaults to the plain transport
 * (defaultFetch); the endpoint resolver's defaults to a guarded one (EndpointOptions). */
export type WellKnownOptions = Omit<wellknown.WellKnownOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the endpoint resolver. `fetch` defaults to the SSRF-guarded
 * createGuardedFetch(), built once per resolver. */
export type EndpointOptions = Omit<wellknown.EndpointOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the registration-requirements reader. `fetch` defaults to the
 * SSRF-guarded createGuardedFetch(), built once per reader. */
export type WellKnownRequirementsOptions = Omit<requirements.WellKnownRequirementsOptions, "fetch"> & {
	fetch?: FetchLike;
};

/** Options for createWBAOfferDirectoryFetch. `fetch` defaults to the SSRF-guarded
 * createGuardedFetch(), built once per fetcher. */
export type WBAOfferDirectoryFetchOptions = Omit<offerKeyCache.WBAOfferDirectoryFetchOptions, "fetch"> & {
	fetch?: FetchLike;
};

/** documents.readManifest, the transport defaulted to createGuardedFetch(). */
export function readManifest(
	domain: string,
	opts: ReadDocumentOptions = {},
): Promise<documents.Document<documents.WellKnownManifest>> {
	return documents.readManifest(domain, { ...opts, fetch: opts.fetch ?? createGuardedFetch() });
}

/** documents.readWBADirectory, the transport defaulted to createGuardedFetch(). */
export function readWBADirectory(
	urlOrDomain: string,
	opts: ReadDocumentOptions = {},
): Promise<documents.Document<documents.WBAFile>> {
	return documents.readWBADirectory(urlOrDomain, { ...opts, fetch: opts.fetch ?? createGuardedFetch() });
}

/** documents.readRevocationList, the transport defaulted to createGuardedFetch(). */
export function readRevocationList(
	url: string,
	opts: ReadDocumentOptions = {},
): Promise<documents.Document<documents.KeyRevocationList>> {
	return documents.readRevocationList(url, { ...opts, fetch: opts.fetch ?? createGuardedFetch() });
}

/** documents.readLicenseDocument, the transport defaulted to createGuardedFetch(). */
export function readLicenseDocument(
	license: documents.License,
	opts: ReadDocumentOptions = {},
): Promise<documents.LicenseDocument> {
	return documents.readLicenseDocument(license, { ...opts, fetch: opts.fetch ?? createGuardedFetch() });
}

/** wba.createWBAKeyResolver, the transport defaulted to the SSRF-guarded one. */
export function createWBAKeyResolver(opts: WBAKeyResolverOptions = {}): wba.WBAKeyResolver {
	return wba.createWBAKeyResolver({ ...opts, fetch: opts.fetch ?? guardedFetch });
}

/** wellknown.createWellKnownKeyResolver, the transport defaulted to the plain one: the
 * JWKS URL is fixed and operator-chosen. */
export function createWellKnownKeyResolver(url: string, opts: WellKnownOptions = {}): wellknown.WellKnownKeyResolver {
	return wellknown.createWellKnownKeyResolver(url, { ...opts, fetch: opts.fetch ?? defaultFetch });
}

/** wellknown.createWellKnownEndpointResolver, the transport defaulted to
 * createGuardedFetch(). Its host is an Offer.exchange domain, so another party chose the
 * address and the provenance rule says guarded, as Go's NewWellKnownEndpointResolver does.
 * An injected `fetch` is used as given. */
export function createWellKnownEndpointResolver(opts: EndpointOptions = {}): wellknown.WellKnownEndpointResolver {
	// Built ONCE per resolver, never per resolve: createGuardedFetch constructs a
	// dispatcher, so a per-resolve default would trade an unguarded dial for a socket
	// leak.
	return wellknown.createWellKnownEndpointResolver({ ...opts, fetch: opts.fetch ?? createGuardedFetch() });
}

/** requirements.createWellKnownRequirementsReader, the transport defaulted to
 * createGuardedFetch(). */
export function createWellKnownRequirementsReader(
	opts: WellKnownRequirementsOptions = {},
): requirements.WellKnownRequirementsReader {
	// Built ONCE per reader, never per read: createGuardedFetch constructs a
	// dispatcher, so a per-read default would trade an unguarded dial for a socket
	// leak.
	return requirements.createWellKnownRequirementsReader({ ...opts, fetch: opts.fetch ?? createGuardedFetch() });
}

/** offerKeyCache.createWBAOfferDirectoryFetch, the transport defaulted to
 * createGuardedFetch(). */
export function createWBAOfferDirectoryFetch(
	opts: WBAOfferDirectoryFetchOptions = {},
): offerKeyCache.OfferDirectoryFetch {
	return offerKeyCache.createWBAOfferDirectoryFetch({ ...opts, fetch: opts.fetch ?? createGuardedFetch() });
}
