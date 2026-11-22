// A signature's lifetime under load, through the public signing surface.
//
// Mirrors sdk/go/core/sigwindow_burst_test.go and
// sdk/python/tests/test_signing_window_burst.py.
//
// The bound: every signature createSigningTransport emits has expires - created equal
// to the window's TTL, and that TTL is at most MAX_SIGNATURE_LIFETIME, whatever the
// request rate. created is the clock's current second, never ahead of it. Each test
// sends requests through the transport with an injected clock and reads created and
// expires back off the Signature-Input header the wrapped send received.
import { describe, it, expect } from "vitest";
import { createSigningTransport, type OutboundInit } from "../core/signing-transport.ts";
import { MAX_SIGNATURE_LIFETIME } from "../core/wba.ts";
import { clockWindow, monotonicWindow, type Window } from "../core/window.ts";

const URL_ = "https://exchange.example/fora.exchange.v1.ExchangeService/DiscoverResources";
const BODY = new TextEncoder().encode('{"query":"x"}') as Uint8Array<ArrayBuffer>;
const DIR = "https://agent.example";

/** A test clock in seconds that the test moves by hand. */
class Clock {
	constructor(public at: number) {}
	readonly now = (): number => this.at;
}

async function transportWith(window?: Window) {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const calls: OutboundInit[] = [];
	const signing = createSigningTransport(
		async (_url, init) => {
			calls.push(init);
			return { status: 200 };
		},
		{
			privKey: kp.privateKey,
			keyid: "test-key.v1",
			signatureAgent: DIR,
			...(window !== undefined ? { window } : {}),
		},
	);
	/** Sends one bodied request and returns the [created, expires] it was signed with. */
	const signedWindow = async (): Promise<[number, number]> => {
		await signing(URL_, { method: "POST", headers: {}, body: BODY });
		const input = calls.at(-1)?.headers?.["signature-input"] ?? "";
		const m = /;created=(\d+);expires=(\d+)/.exec(input);
		if (m === null) throw new Error(`Signature-Input carries no created/expires pair: ${input}`);
		return [Number(m[1]), Number(m[2])];
	};
	return { signing, calls, signedWindow };
}

describe("a signature's lifetime under a burst stays the window's TTL", () => {
	for (const [name, make] of [
		["monotonicWindow", monotonicWindow],
		["clockWindow", clockWindow],
	] as const) {
		it(`${name}: 10 rps for one simulated minute, then 200 requests in one second`, async () => {
			// The old one-second-per-request shift had grown the last window of the minute
			// by about nine minutes.
			const ttl = 30;
			const clock = new Clock(1_700_000_000);
			const { signedWindow } = await transportWith(make(clock.now, ttl));
			for (let i = 0; i < 600; i += 1) {
				const [created, expires] = await signedWindow();
				expect(expires - created, `request ${i}`).toBe(ttl);
				expect(created, `request ${i}`).toBe(Math.floor(clock.at));
				clock.at += 0.1;
			}
			for (let i = 0; i < 200; i += 1) {
				const second = Math.floor(clock.at);
				expect(await signedWindow(), `request ${600 + i}`).toEqual([second, second + ttl]);
			}
			// 800 Ed25519 signatures through WebCrypto; the first run in a cold worker is slow.
		}, 30_000);
	}

	it("follows a clock that goes backwards", async () => {
		const clock = new Clock(1_700_000_100);
		const { signedWindow } = await transportWith(monotonicWindow(clock.now, 30));
		for (let i = 0; i < 50; i += 1) await signedWindow();
		clock.at -= 40;
		expect(await signedWindow()).toEqual([1_700_000_060, 1_700_000_090]);
	});

	it("signs a window of exactly MAX_SIGNATURE_LIFETIME", async () => {
		const { signedWindow } = await transportWith(
			monotonicWindow(new Clock(1_700_000_000).now, MAX_SIGNATURE_LIFETIME),
		);
		for (let i = 0; i < 100; i += 1) {
			const [created, expires] = await signedWindow();
			expect(expires - created).toBe(MAX_SIGNATURE_LIFETIME);
		}
	});

	it("refuses a window one second over MAX_SIGNATURE_LIFETIME and sends nothing", async () => {
		const { signing, calls } = await transportWith(
			clockWindow(new Clock(1_700_000_000).now, MAX_SIGNATURE_LIFETIME + 1),
		);
		await expect(signing(URL_, { method: "POST", headers: {}, body: BODY })).rejects.toMatchObject({
			reason: "signature_lifetime",
		});
		expect(calls).toHaveLength(0);
	});

	it("the default window, read from the real clock, stamps MAX_SIGNATURE_LIFETIME under a burst", async () => {
		const { signedWindow } = await transportWith();
		const before = Math.floor(Date.now() / 1000);
		for (let i = 0; i < 500; i += 1) {
			const [created, expires] = await signedWindow();
			expect(expires - created, `request ${i}`).toBe(MAX_SIGNATURE_LIFETIME);
			expect(created).toBeGreaterThanOrEqual(before);
			expect(created).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
		}
	});
});
