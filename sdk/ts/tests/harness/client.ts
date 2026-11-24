// What a client replay drives the client through: a recording send or a real server on a
// loopback port, the flags that let the client dial it, the agent's keys and a verified
// offer to execute, and the failure a call ends in.

import { createServer, type RequestListener, type Server } from "node:http";
import { ForaCallError, type UnaryRequest, type UnarySend } from "@fora-protocol/sdk-l1/client";
import { createVerifier, type VerifiedOffer } from "@fora-protocol/sdk-l1/core";
import { signOffer } from "@fora-protocol/sdk-l1/offer-sign";
import { expect } from "vitest";

/** Start a real server on 127.0.0.1 at a free port; resolves to it and its port. */
export async function listenLoopback(handler: RequestListener): Promise<[Server, number]> {
	const server = createServer(handler);
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
	return [server, (server.address() as { port: number }).port];
}

/** Run `run` with SKIP_SSRF and ALLOW_INSECURE set, so the client dials a loopback,
 * plaintext target, and restore both after. */
export async function withLoopback<T>(run: () => Promise<T>): Promise<T> {
	const saved = [process.env.SKIP_SSRF, process.env.ALLOW_INSECURE];
	process.env.SKIP_SSRF = "true";
	process.env.ALLOW_INSECURE = "true";
	try {
		return await run();
	} finally {
		if (saved[0] === undefined) delete process.env.SKIP_SSRF;
		else process.env.SKIP_SSRF = saved[0];
		if (saved[1] === undefined) delete process.env.ALLOW_INSECURE;
		else process.env.ALLOW_INSECURE = saved[1];
	}
}

/** What `p` rejects with, or undefined when it resolves. */
export function rejection(p: Promise<unknown>): Promise<unknown> {
	return p.then(
		() => undefined,
		(e: unknown) => e,
	);
}

/** The ForaCallError `p` rejects with; fails the test when it resolves or rejects with
 * anything else. */
export async function callError(p: Promise<unknown>): Promise<ForaCallError> {
	try {
		await p;
	} catch (e) {
		expect(e).toBeInstanceOf(ForaCallError);
		return e as ForaCallError;
	}
	throw new Error("the call did not fail");
}

/** A PushResources message listing one free resource. */
export function samplePush(): Record<string, unknown> {
	return {
		exchange: "exchange.test",
		tenant_id: "tenant-1",
		entries: [
			{
				domain: "publisher.test",
				path: "/x",
				terms: [
					{
						semantics: "TERM_SEMANTICS_ENUMERATED",
						pricing: { model: "PRICING_MODEL_FREE", rate: "0" },
					},
				],
			},
		],
	};
}

/** A send that records every request it is handed and answers `answer` as JSON. */
export function recordingSend(answer: unknown, status = 200): { send: UnarySend; seen: UnaryRequest[] } {
	const seen: UnaryRequest[] = [];
	const send: UnarySend = async (req) => {
		seen.push(req);
		return { status, body: JSON.stringify(answer) };
	};
	return { send, seen };
}

/** A fresh, extractable Ed25519 key pair. */
export async function agentKeys(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
}

/** An offer of exchange.test, signed by a fresh key and verified by a strict verifier
 * that resolves that key. */
export async function verifiedOffer(): Promise<VerifiedOffer> {
	const kp = await agentKeys();
	const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)) as Uint8Array<ArrayBuffer>;
	const offer: Record<string, unknown> = {
		offer_id: "offer-good",
		exchange: "exchange.test",
		expires_at: "2099-01-01T00:00:00Z",
	};
	const signature = await signOffer(offer, kp.privateKey);
	const signed = { ...offer, signature, signature_algorithm: "EdDSA" };
	const sorted = await createVerifier("strict", {
		resolve: async () => publicKey,
		now: () => Date.parse("2024-01-01T00:00:00Z"),
	}).sort([signed]);
	const first = sorted.verified[0];
	if (first === undefined) {
		throw new Error(`fixture offer did not verify: ${sorted.rejected[0]?.reason}`);
	}
	return first;
}
