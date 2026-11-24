// The collaborators a request-signature replay injects: key resolvers that record what
// they were asked for, an in-memory replay store, a fixed clock, the header bag a vector
// describes, and a send that captures what a transport forwards.

import type { ReplayStore, RequestKeyResolver, VerifyRequestHeaders } from "../../core/verify-request.ts";

/** A resolver that finds a key only under the directory it was registered in, and
 * records every (directory, keyid) it was asked for. */
export function directoryResolver(
	entries: Array<{ directory: string; keyid: string; pub: Uint8Array<ArrayBuffer> }>,
): RequestKeyResolver & { calls: Array<[string, string]> } {
	const keys = new Map(entries.map((e) => [`${e.directory} ${e.keyid}`, e.pub]));
	const calls: Array<[string, string]> = [];
	return {
		calls,
		resolve(keyid, directory) {
			calls.push([directory, keyid]);
			return keys.get(`${directory} ${keyid}`);
		},
	};
}

/** A resolver keyed by keyid alone, whatever the directory, that records every keyid it
 * was asked for. */
export function keyidResolver(keys: Record<string, Uint8Array<ArrayBuffer>>): RequestKeyResolver & { calls: string[] } {
	const calls: string[] = [];
	return {
		calls,
		resolve(keyid) {
			calls.push(keyid);
			return keys[keyid];
		},
	};
}

/** A replay store over one in-memory set; the SDK ships none. */
export function memoryReplayStore(): ReplayStore {
	const seen = new Set<string>();
	return {
		async seenNonce(nonce) {
			return seen.has(nonce);
		},
		async seenOrAdd(nonce) {
			if (seen.has(nonce)) return true;
			seen.add(nonce);
			return false;
		},
	};
}

/** A clock that always reads `nowUnix` (seconds). */
export const fixedClock = (nowUnix: number) => () => nowUnix;

/** The header columns of a request-signature vector. */
export interface SignedHeaderColumns {
	content_digest: string;
	signature_input: string;
	signature: string;
	authorization: string;
	signature_agent: string;
	/** An X-Entitlement-Token value the signature does not cover. */
	entitlement?: string;
	/** Names the request does NOT carry. */
	omit_headers?: string[];
	/** Field lines added beside the base ones, spelled in a different case. */
	extra_headers?: Record<string, string>;
}

/** The header bag a vector describes: the base five, minus what the request does not
 * carry, plus any extra field line spelled in another case. The omitted names are
 * deleted after the base ones are set, so a face sees a covered name with no field line
 * rather than an empty one; the extras land after the base ones, so the join order
 * matches the order the oracle added them. */
export function headersFor(v: SignedHeaderColumns): VerifyRequestHeaders {
	const headers: VerifyRequestHeaders = {
		"content-digest": v.content_digest,
		"signature-input": v.signature_input,
		signature: v.signature,
		authorization: v.authorization,
		"signature-agent": v.signature_agent,
	};
	if (v.entitlement) headers["x-entitlement-token"] = v.entitlement;
	const bag = headers as Record<string, string | undefined>;
	for (const name of v.omit_headers ?? []) delete bag[name.toLowerCase()];
	for (const [name, value] of Object.entries(v.extra_headers ?? {})) bag[name] = value;
	return headers;
}

/** One hop of a multi-signature vector. */
export type MultisigHop = {
	keyid: string;
	pubkey_b64url: string;
	seed_hex: string;
	directory: string;
	nonce?: string;
	cover_previous?: boolean;
};

/** A row of multisig-chain-vectors.json. */
export type MultisigChainVector = SignedHeaderColumns & {
	name: string;
	method: string;
	url: string;
	body_hex: string;
	created: number;
	expires: number;
	hops: MultisigHop[];
	max_signatures: number;
	expected_verified: boolean;
	expected_keyids: string[] | null;
	expected_directories: string[] | null;
	expected_reason: string;
};

/** The request a WHATWG-fetch-shaped send is handed. */
export type SendInit = {
	method?: string;
	headers?: Record<string, string>;
	body?: Uint8Array<ArrayBuffer>;
};
export type Captured = { url: string; init: SendInit };

/** A send that answers 200 and records every call it was handed. */
export function capturingSend(): {
	send: (url: string, init: SendInit) => Promise<{ status: number }>;
	calls: Captured[];
} {
	const calls: Captured[] = [];
	const send = async (url: string, init: SendInit) => {
		calls.push({ url, init });
		return { status: 200 };
	};
	return { send, calls };
}
