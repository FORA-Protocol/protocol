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
import { defaultFetch, guardedFetch, guardedFetchFromEnv } from "./http.ts";
import * as offerKeyCache from "./offer-key-cache.ts";
import * as requirements from "./registration-requirements.ts";
import * as wba from "./wba.ts";
import * as wellknown from "./wellknown.ts";

/** How a document reader dials. `fetch` defaults to guardedFetchFromEnv(), built for
 * the call. */
export type ReadDocumentOptions = Omit<documents.ReadDocumentOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the WBA resolver. `fetch` defaults to the SSRF-guarded transport: the
 * directory host comes from the request-supplied Signature-Agent and is fetched
 * pre-auth (matches the Go oracle). */
export type WBAKeyResolverOptions = Omit<wba.WBAKeyResolverOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the well-known fetching resolvers. `fetch` defaults to the plain
 * transport (defaultFetch). */
export type WellKnownOptions = Omit<wellknown.WellKnownOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the endpoint resolver. `fetch` defaults to the plain transport. */
export type EndpointOptions = Omit<wellknown.EndpointOptions, "fetch"> & { fetch?: FetchLike };

/** Options for the registration-requirements reader. `fetch` defaults to the
 * SSRF-guarded guardedFetchFromEnv(), built once per reader. */
export type WellKnownRequirementsOptions = Omit<requirements.WellKnownRequirementsOptions, "fetch"> & {
	fetch?: FetchLike;
};

/** Options for createWBAOfferDirectoryFetch. `fetch` defaults to the SSRF-guarded
 * guardedFetchFromEnv(), built once per fetcher. */
export type WBAOfferDirectoryFetchOptions = Omit<offerKeyCache.WBAOfferDirectoryFetchOptions, "fetch"> & {
	fetch?: FetchLike;
};

/** documents.readManifest, the transport defaulted to guardedFetchFromEnv(). */
export function readManifest(
	domain: string,
	opts: ReadDocumentOptions = {},
): Promise<documents.Document<documents.WellKnownManifest>> {
	return documents.readManifest(domain, { ...opts, fetch: opts.fetch ?? guardedFetchFromEnv() });
}

/** documents.readWBADirectory, the transport defaulted to guardedFetchFromEnv(). */
export function readWBADirectory(
	urlOrDomain: string,
	opts: ReadDocumentOptions = {},
): Promise<documents.Document<documents.WBAFile>> {
	return documents.readWBADirectory(urlOrDomain, { ...opts, fetch: opts.fetch ?? guardedFetchFromEnv() });
}

/** documents.readRevocationList, the transport defaulted to guardedFetchFromEnv(). */
export function readRevocationList(
	url: string,
	opts: ReadDocumentOptions = {},
): Promise<documents.Document<documents.KeyRevocationList>> {
	return documents.readRevocationList(url, { ...opts, fetch: opts.fetch ?? guardedFetchFromEnv() });
}

/** documents.readLicenseDocument, the transport defaulted to guardedFetchFromEnv(). */
export function readLicenseDocument(
	license: documents.License,
	opts: ReadDocumentOptions = {},
): Promise<documents.LicenseDocument> {
	return documents.readLicenseDocument(license, { ...opts, fetch: opts.fetch ?? guardedFetchFromEnv() });
}

/** wba.createWBAKeyResolver, the transport defaulted to the SSRF-guarded one. */
export function createWBAKeyResolver(opts: WBAKeyResolverOptions = {}): wba.WBAKeyResolver {
	return wba.createWBAKeyResolver({ ...opts, fetch: opts.fetch ?? guardedFetch });
}

/** wellknown.createWellKnownKeyResolver, the transport defaulted to the plain one: the
 * JWKS URL is fixed and operator-chosen. */
export function createWellKnownKeyResolver(
	url: string,
	opts: WellKnownOptions = {},
): wellknown.WellKnownKeyResolver {
	return wellknown.createWellKnownKeyResolver(url, { ...opts, fetch: opts.fetch ?? defaultFetch });
}

/** wellknown.createWellKnownEndpointResolver, the transport defaulted to the plain one.
 * Its host is an Offer.exchange domain, so the provenance rule says guarded; Go already
 * guards it, and this default has not caught up. */
export function createWellKnownEndpointResolver(opts: EndpointOptions = {}): wellknown.WellKnownEndpointResolver {
	return wellknown.createWellKnownEndpointResolver({ ...opts, fetch: opts.fetch ?? defaultFetch });
}

/** requirements.createWellKnownRequirementsReader, the transport defaulted to
 * guardedFetchFromEnv(). */
export function createWellKnownRequirementsReader(
	opts: WellKnownRequirementsOptions = {},
): requirements.WellKnownRequirementsReader {
	// Built ONCE per reader, never per read: guardedFetchFromEnv constructs a
	// dispatcher, so a per-read default would trade an unguarded dial for a socket
	// leak.
	return requirements.createWellKnownRequirementsReader({ ...opts, fetch: opts.fetch ?? guardedFetchFromEnv() });
}

/** offerKeyCache.createWBAOfferDirectoryFetch, the transport defaulted to
 * guardedFetchFromEnv(). */
export function createWBAOfferDirectoryFetch(
	opts: WBAOfferDirectoryFetchOptions = {},
): offerKeyCache.OfferDirectoryFetch {
	return offerKeyCache.createWBAOfferDirectoryFetch({ ...opts, fetch: opts.fetch ?? guardedFetchFromEnv() });
}
