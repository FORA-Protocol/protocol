// The canonical acceptance renderer and the checks around it, shared by the protocol's
// acceptance signers (acceptance.ts) and the test signers (testing.ts).
//
// Deliberately not exported from the package manifest: none of this is an API of its
// own. The requester check is a parameter, run at the exact position the protocol's
// signer runs it, and every other check is this module's. acceptance.ts passes the check
// fora.proto requires of a signer; testing.ts passes one that admits an empty requester.
// One renderer and one copy of every other check serve both, so neither can drift.
// Mirror of Go internal/canonicalsign and the private renderers in Python's core.

import canonicalize from "canonicalize";

import type { AcceptanceInput, RequestAcceptanceInput } from "./acceptance.ts";
import { utf8Bytes } from "./base64url.ts";

/** Refuses a requester an acceptance may not name, given its id and domain, by throwing. */
export type RequesterCheck = (requesterId: string, requesterDomain: string) => void;

/**
 * renderAcceptance reproduces the canonical signed bytes:
 * JCS(protojson(AgentAcceptancePayload)) with every empty string field omitted. Throws on
 * an empty offer signature, then on whatever `check` refuses.
 */
export function renderAcceptance(input: AcceptanceInput, check: RequesterCheck): Uint8Array<ArrayBuffer> {
	if (input.offerSig === "") {
		throw new Error(
			"fora/acceptance: cannot accept an unsigned offer (empty offer signature)",
		);
	}
	check(input.requesterId, input.requesterDomain);
	// proto omit-unpopulated: every empty string field is absent before JCS. The Go
	// oracle gets that structurally from EmitUnpopulated=false; this record is
	// hand-built, so the omission is applied once over the whole record rather than
	// per key. The filter tests for the empty STRING, which covers every member
	// AgentAcceptancePayload has (the field-set guard in the Go suite pins that list), so
	// a string field added to the message cannot arrive without its omission. A
	// non-string field would need its own zero-value test.
	const payload: Record<string, string> = {
		offer_sig: input.offerSig,
		requester_id: input.requesterId,
		requester_domain: input.requesterDomain,
		idempotency_key: input.idempotencyKey,
	};
	const obj = Object.fromEntries(Object.entries(payload).filter(([, v]) => v !== ""));
	const jcs = canonicalize(obj);
	if (jcs === undefined) {
		throw new Error("fora/acceptance: payload is not JSON-serializable");
	}
	return utf8Bytes(jcs);
}

/** Canonical JCS(protojson(...)) bytes for the complete ordered execute set. Throws on
 * whatever `check` refuses, then on no items, then on an item with an empty offer
 * signature or exchange. */
export function renderRequestAcceptance(
	input: RequestAcceptanceInput,
	check: RequesterCheck,
): Uint8Array<ArrayBuffer> {
	check(input.requesterId, input.requesterDomain);
	if (input.items.length === 0) {
		throw new Error("fora/acceptance: request acceptance requires at least one item");
	}
	const items = input.items.map((item, index) => {
		if (item.offerSig === "") {
			throw new Error(
				`fora/acceptance: request item ${index} has an empty offer signature`,
			);
		}
		if (item.exchange === "") {
			throw new Error(`fora/acceptance: request item ${index} has an empty exchange`);
		}
		return { offer_sig: item.offerSig, exchange: item.exchange };
	});
	const payload: Record<string, unknown> = {
		items,
		requester_id: input.requesterId,
		requester_domain: input.requesterDomain,
		idempotency_key: input.idempotencyKey,
	};
	const obj = Object.fromEntries(
		Object.entries(payload).filter(([, value]) => value !== ""),
	);
	const jcs = canonicalize(obj);
	if (jcs === undefined) {
		throw new Error("fora/acceptance: request payload is not JSON-serializable");
	}
	return utf8Bytes(jcs);
}

/** signPayload signs canonical acceptance bytes with the agent's Ed25519 key and returns
 * the hex signature an AgentAcceptance or AgentRequestAcceptance carries. */
export async function signPayload(
	payload: Uint8Array<ArrayBuffer>,
	privateKey: CryptoKey,
): Promise<string> {
	const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, payload));
	let hex = "";
	for (const b of sig) hex += b.toString(16).padStart(2, "0");
	return hex;
}
