// The rows of acceptance-vectors.json and request-acceptance-vectors.json, as the inputs
// the SDK's acceptance faces take.

import { utf8Bytes } from "@fora-protocol/sdk-l1/base64url";
import { expect } from "vitest";
import { hexToBytes, importVerifyKey } from "./keys.ts";

/** The requester columns both acceptance corpora carry. */
export type AcceptanceRequester = { requester_id: string; requester_domain: string; idempotency_key: string };
/** The signature columns both acceptance corpora carry. */
export type AcceptanceSigned = { canonical_jcs: string; signature_hex: string; pubkey_b64: string; seed_hex: string };

/** The offer-acceptance input a row of acceptance-vectors.json describes. */
export function offerInput(row: AcceptanceRequester & { offer_sig: string }) {
	return {
		offerSig: row.offer_sig,
		requesterId: row.requester_id,
		requesterDomain: row.requester_domain,
		idempotencyKey: row.idempotency_key,
	};
}

/** The request-acceptance input a row of request-acceptance-vectors.json describes. */
export function requestInput(row: AcceptanceRequester & { items: { offer_sig: string; exchange: string }[] }) {
	return {
		items: row.items.map((i) => ({ offerSig: i.offer_sig, exchange: i.exchange })),
		requesterId: row.requester_id,
		requesterDomain: row.requester_domain,
		idempotencyKey: row.idempotency_key,
	};
}

/** Assert the row's recorded signature verifies over its recorded bytes, so a refusal of
 * them is a refusal of the requester alone. */
export async function expectTheRecordedSignatureVerifies(row: AcceptanceSigned): Promise<void> {
	const ok = await crypto.subtle.verify(
		"Ed25519",
		await importVerifyKey(row.pubkey_b64),
		hexToBytes(row.signature_hex),
		utf8Bytes(row.canonical_jcs),
	);
	expect(ok).toBe(true);
}
