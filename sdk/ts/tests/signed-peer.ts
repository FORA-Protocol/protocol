// A peer behind the client's injected send that authenticates every request first.
//
// A recording send proves the bytes were sent; it cannot prove a server would have
// ACCEPTED them. A request altered before it is signed is only useful if the signature
// covers the altered bytes, so this peer runs the SDK's own server-side verifier on every
// request and answers one that fails with the 401 envelope an Exchange sends.

import type { UnaryRequest, UnaryResponse, UnarySend } from "../client/index.ts";
import { type VerifyRequestHeaders, verifyRequestServer } from "../core/verify-request.ts";

export interface Received {
	request: UnaryRequest;
	valid: boolean;
	body: string;
}

export interface SignedPeer {
	send: UnarySend;
	seen: Received[];
	only(): Received;
}

/** The fixture agent: a key pair and the keyid it signs under. */
export async function agentKeys(): Promise<{ keys: CryptoKeyPair; pub: Uint8Array<ArrayBuffer> }> {
	const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const pub = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)) as Uint8Array<ArrayBuffer>;
	return { keys, pub };
}

/** A peer that resolves `keyid` to `pub`, verifies, then answers with `answer`. */
export function signedPeer(
	keyid: string,
	pub: Uint8Array<ArrayBuffer>,
	answer: (req: UnaryRequest) => UnaryResponse = () => ({
		status: 200,
		body: JSON.stringify({ ver: "1.0", exchange: "exchange.test" }),
	}),
): SignedPeer {
	const seen: Received[] = [];
	const send: UnarySend = async (req) => {
		const headers: Record<string, string> = {};
		for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
		const verdict = await verifyRequestServer({
			method: "POST",
			url: req.url,
			body: req.body,
			headers: headers as VerifyRequestHeaders,
			resolve: { resolve: (k) => (k === keyid ? pub : undefined) },
			now: () => Math.floor(Date.now() / 1000),
		});
		seen.push({ request: req, valid: verdict.valid, body: new TextDecoder().decode(req.body) });
		if (!verdict.valid) {
			return {
				status: 401,
				body: JSON.stringify({ code: "unauthenticated", message: verdict.reason ?? "signature" }),
			};
		}
		return answer(req);
	};
	return {
		send,
		seen,
		only() {
			if (seen.length !== 1) throw new Error(`expected exactly one request, peer saw ${seen.length}`);
			return seen[0] as Received;
		},
	};
}
