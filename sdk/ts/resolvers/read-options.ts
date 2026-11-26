// How a document reader dials. Edge-safe: the transport is the caller's.

import type { Ed25519Verify } from "../src/pop.ts";
import type { FetchLike } from "./fetch.ts";

/** How a document reader dials. */
export interface ReadDocumentOptions {
	/** The transport. Required here; the Node entry's readers default it to
	 * createGuardedFetch(), built for the call. */
	fetch: FetchLike;
	/** The scheme of a URL a reader builds from a domain. Only "https" is accepted, or
	 * nothing; any other value fails the read with DirectoryUnavailable before anything
	 * is dialled.
	 * @deprecated A URL a reader builds is always https, so leave it unset. Removed in
	 * 2.0. */
	scheme?: string;
	/** The Ed25519 verify primitive readWBADirectory checks the directory's response
	 * signatures with, for a runtime without WebCrypto Ed25519. Defaults to WebCrypto. */
	verifyEd25519?: Ed25519Verify;
	/** The clock, in epoch milliseconds, readWBADirectory judges the directory's response
	 * signatures at. Defaults to Date.now. Only readWBADirectory reads it. */
	now?: () => number;
}
