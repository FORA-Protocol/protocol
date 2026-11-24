// What a client replay drives the client through: a real server on a loopback port, the
// flags that let the client dial it, and the failure a call ends in.

import { createServer, type RequestListener, type Server } from "node:http";
import { expect } from "vitest";
import { ForaCallError } from "../../client/errors.ts";

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
