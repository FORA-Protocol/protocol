// The refusals of the acceptance canonicalizers and signers, pinned: the exact text, and
// which refusal wins when an input has several faults. The renderer and the checks around
// it are shared with code that skips one of them (src/testing.ts), so the order and the
// wording are part of what must not move. Mirrors sdk/python/tests/test_acceptance_refusals.py.
import { describe, expect, it } from "vitest";

import {
	type AcceptanceInput,
	acceptancePayload,
	type RequestAcceptanceInput,
	requestAcceptancePayload,
	signOfferAcceptance,
	signRequestAcceptance,
	verifyOfferAcceptance,
	verifyRequestAcceptance,
} from "../src/acceptance.ts";

const UNSIGNED = "fora/acceptance: cannot accept an unsigned offer (empty offer signature)";
const NO_ID = "fora/acceptance: acceptance names an empty requester: requesterId is empty";
const NO_DOMAIN = "fora/acceptance: acceptance names an empty requester: requesterDomain is empty";
const NO_ITEMS = "fora/acceptance: request acceptance requires at least one item";

const named = { requesterId: "agent-1", requesterDomain: "agent.example", idempotencyKey: "idem" };

async function keyPair(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
}

describe("offer acceptance refusals", () => {
	const cases: [string, AcceptanceInput, string][] = [
		["an unsigned offer", { ...named, offerSig: "" }, UNSIGNED],
		["no requester id", { ...named, offerSig: "sig", requesterId: "" }, NO_ID],
		["no requester domain", { ...named, offerSig: "sig", requesterDomain: "" }, NO_DOMAIN],
		["an unsigned offer before an empty requester", { ...named, offerSig: "", requesterId: "" }, UNSIGNED],
		["no id before no domain", { ...named, offerSig: "sig", requesterId: "", requesterDomain: "" }, NO_ID],
	];
	for (const [name, input, message] of cases) {
		it(name, async () => {
			const keys = await keyPair();
			expect(() => acceptancePayload(input)).toThrow(new Error(message));
			await expect(signOfferAcceptance(input, keys.privateKey)).rejects.toThrow(new Error(message));
			expect(await verifyOfferAcceptance(input, "00", keys.publicKey)).toBe(false);
		});
	}
});

describe("request acceptance refusals", () => {
	const item = { offerSig: "sig", exchange: "one.example" };
	const cases: [string, RequestAcceptanceInput, string][] = [
		["no items", { ...named, items: [] }, NO_ITEMS],
		[
			"an item with no offer signature",
			{ ...named, items: [{ offerSig: "", exchange: "one.example" }] },
			"fora/acceptance: request item 0 has an empty offer signature",
		],
		[
			"an item naming no exchange",
			{ ...named, items: [{ offerSig: "sig", exchange: "" }] },
			"fora/acceptance: request item 0 has an empty exchange",
		],
		[
			"the second item",
			{ ...named, items: [item, { offerSig: "", exchange: "one.example" }] },
			"fora/acceptance: request item 1 has an empty offer signature",
		],
		["no requester id", { ...named, requesterId: "", items: [item] }, NO_ID],
		["no requester domain", { ...named, requesterDomain: "", items: [item] }, NO_DOMAIN],
		["an empty requester before no items", { ...named, requesterId: "", items: [] }, NO_ID],
		[
			"an empty requester before an empty item field",
			{ ...named, requesterDomain: "", items: [{ offerSig: "", exchange: "" }] },
			NO_DOMAIN,
		],
		[
			"an empty offer signature before an empty exchange",
			{ ...named, items: [{ offerSig: "", exchange: "" }] },
			"fora/acceptance: request item 0 has an empty offer signature",
		],
	];
	for (const [name, input, message] of cases) {
		it(name, async () => {
			const keys = await keyPair();
			expect(() => requestAcceptancePayload(input)).toThrow(new Error(message));
			await expect(signRequestAcceptance(input, keys.privateKey)).rejects.toThrow(new Error(message));
			expect(await verifyRequestAcceptance(input, "00", keys.publicKey)).toBe(false);
		});
	}
});
