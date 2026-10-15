// Acceptance signers that admit an empty requester, for a test proving that a verifier
// refuses them.
//
// fora.proto requires an acceptance to name its requester: "A signer refuses to sign bytes
// that name an empty requester, and a verifier refuses an acceptance whose canonical bytes
// name one, even when the signature over those bytes verifies." The signers in
// ./acceptance are that signer, so they cannot produce the one input a verifier's refusal
// is tested with. The four functions here are their twins with that single refusal
// skipped. They render through the same canonical form and keep every other refusal, so
// an acceptance they sign is valid in every respect but the requester, and a verifier's
// refusal of it is attributable to that alone. The `refused` lists of the shared
// acceptance-vectors.json and request-acceptance-vectors.json record exactly what they
// produce.
//
// Test support, published as @fora-protocol/sdk/testing: nothing in the SDK imports it,
// and an acceptance it signs is one a conforming party must never send. Go's helperstest
// and Python's fora_sdk.testing are its twins. WebCrypto only, so it runs wherever the
// acceptance signers do.

import type { AcceptanceInput, RequestAcceptanceInput } from "./acceptance.ts";
import { renderAcceptance, renderRequestAcceptance, signPayload } from "./acceptance-render.ts";

/** Admits every requester, an empty one included. Not exported, so nothing outside this
 * module can hand it to the renderer the signers share. */
function anyRequester(): void {}

/** acceptancePayload (./acceptance) without its refusal of an empty requesterId or
 * requesterDomain. */
export function acceptancePayloadAnyRequester(input: AcceptanceInput): Uint8Array<ArrayBuffer> {
	return renderAcceptance(input, anyRequester);
}

/** signOfferAcceptance (./acceptance) without its refusal of an empty requesterId or
 * requesterDomain. */
export async function signOfferAcceptanceAnyRequester(
	input: AcceptanceInput,
	privateKey: CryptoKey,
): Promise<string> {
	return signPayload(acceptancePayloadAnyRequester(input), privateKey);
}

/** requestAcceptancePayload (./acceptance) without its refusal of an empty requesterId
 * or requesterDomain. */
export function requestAcceptancePayloadAnyRequester(
	input: RequestAcceptanceInput,
): Uint8Array<ArrayBuffer> {
	return renderRequestAcceptance(input, anyRequester);
}

/** signRequestAcceptance (./acceptance) without its refusal of an empty requesterId or
 * requesterDomain. */
export async function signRequestAcceptanceAnyRequester(
	input: RequestAcceptanceInput,
	privateKey: CryptoKey,
): Promise<string> {
	return signPayload(requestAcceptancePayloadAnyRequester(input), privateKey);
}
