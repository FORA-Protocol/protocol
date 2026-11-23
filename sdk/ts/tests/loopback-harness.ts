// How a suite reaches its in-process plaintext listener through the SDK's public seams.
//
// The SDK dials https only on every leg that reaches a host another party named, and its
// guarded transports refuse loopback, and no switch turns either check off. So a test
// addresses its peer with an https URL for a 127.0.0.1 origin and injects a transport that
// routes that URL to the origin's plaintext listener, through the same option a deployment
// uses to reach a private peer: a resolver's `fetch` (httpsToLoopback in
// resolvers-harness.ts), the client's `send` and `guardedSend` (loopbackSend), or the
// delivery fetch's `dispatcher` (loopbackDispatcher). The host, and so every signature's
// @authority and @target-uri, is left as the SDK built it; only the dial is plaintext.
//
// A test of the guarded fetch's own composition cannot inject a transport, and the guard
// refuses every loopback address. It addresses a public address instead, and routeTlsDial
// routes Node's TLS dial to that address to the plaintext listener, below every layer of
// the SDK, so the scheme check, the address check and the redirect policy all run as in
// production.

import net, { type NetConnectOpts, connect as netConnect, type Server, type Socket } from "node:net";
import tls from "node:tls";

import { Agent, type Dispatcher } from "undici";
import { vi } from "vitest";

import { createUnarySend } from "../client/send.ts";
import type { UnarySend } from "../client/transport.ts";

const HTTPS_LOOPBACK = /^https:\/\/127\.0\.0\.1:/;

/** The plaintext URL of an https URL for a 127.0.0.1 origin; any other URL unchanged. */
export function toPlaintextLoopback(url: string): string {
	return url.replace(HTTPS_LOOPBACK, "http://127.0.0.1:");
}

/** Start `server` on 127.0.0.1 and a free port, and return the port. */
export async function listenLoopback(server: Server): Promise<number> {
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (address === null || typeof address === "string") throw new Error("no port");
	return address.port;
}

/** The https URL of a 127.0.0.1 listener on `port`, joined with `path`. */
export function httpsLoopback(port: number, path = ""): string {
	return `https://127.0.0.1:${port}${path}`;
}

/** The https spelling of a plaintext URL, the address a test hands the SDK for a listener
 * it serves over plaintext. */
export function httpsOf(url: string): string {
	return url.replace(/^http:/, "https:");
}

/** An undici Dispatcher, unguarded, that dials an https origin on 127.0.0.1 over plaintext.
 * Injected as the delivery fetch's `dispatcher`. It follows no redirect, like the default;
 * `options` tune its pool. */
export function loopbackDispatcher(options?: Agent.Options): Dispatcher {
	return new Agent(options).compose(
		(dispatch) => (opts, handler) => dispatch({ ...opts, origin: toPlaintextLoopback(String(opts.origin)) }, handler),
	);
}

/** The SDK's own unguarded send, dialing an https URL for a 127.0.0.1 origin over
 * plaintext. Injected as the client's `send` or `guardedSend`; everything else the send
 * does — the byte bound, the coding refusal, the redirect refusal — is the SDK's own. */
export function loopbackSend(): UnarySend {
	const plain = createUnarySend({ guarded: false });
	return (req) => plain({ ...req, url: toPlaintextLoopback(req.url) });
}

/** Route every TLS dial to `address` to the plaintext listener on 127.0.0.1:`port`, until
 * the returned function restores node:tls and node:net. The socket skips the handshake and
 * reports it done once the TCP connection is up, so everything above the dial runs
 * unchanged. A TLS dial to any other host, and a plaintext dial to `address`, throws, so
 * nothing the guarded fetch dials leaves the machine. */
export function routeTlsDial(address: string, port: number): () => void {
	const route = (options: tls.ConnectionOptions): tls.TLSSocket => {
		if (options.host !== address) throw new Error(`the test network reaches only ${address}, not ${options.host}`);
		const socket = netConnect({ host: "127.0.0.1", port });
		socket.once("connect", () => socket.emit("secureConnect"));
		return socket as tls.TLSSocket;
	};
	const plaintext = (options: NetConnectOpts): Socket => {
		if ("host" in options && options.host === address) throw new Error(`the test network has no plaintext ${address}`);
		return netConnect(options);
	};
	const spies = [
		vi.spyOn(tls, "connect").mockImplementation(route as typeof tls.connect),
		vi.spyOn(net, "connect").mockImplementation(plaintext as typeof net.connect),
	];
	return () => {
		for (const spy of spies) spy.mockRestore();
	};
}
