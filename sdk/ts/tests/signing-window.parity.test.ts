// Signing-window parity: replay sdk/go/core/testdata/signing-window-vectors.json.
//
// Each row names a window kind, its TTL and a sequence of clock readings in unix
// milliseconds. Every reading is one request through createSigningTransport with the
// clock set to that reading, and the row records, per request, the created and expires
// the Go signing transport stamped, and expected_reason: "" for a signed request, the
// refusal token when it refused and sent nothing. The window kinds map to clockWindow,
// monotonicWindow and, for "default", a transport given no window, which builds its own
// from Date.now with the default TTL; those rows move Date.now with fake timers.
import { afterEach, describe, expect, it, vi } from "vitest";
import corpus from "../../go/core/testdata/signing-window-vectors.json";
import { createSigningTransport } from "../core/signing-transport.ts";
import { MAX_SIGNATURE_LIFETIME } from "../core/wba.ts";
import { clockWindow, monotonicWindow, type Window } from "../core/window.ts";
import { genSigner } from "./harness/keys.ts";
import { capturingSend } from "./harness/requests.ts";

type Expectation = { created?: number; expires?: number; expected_reason: string };
type SigningWindowVector = {
	name: string;
	window: string;
	ttl_sec: number;
	clock_ms: number[];
	expected: Expectation[];
};

const VECTORS = corpus.vectors as SigningWindowVector[];
const URL_ = "https://exchange.example/fora.exchange.v1.ExchangeService/DiscoverResources";
const BODY = new TextEncoder().encode('{"test":true}') as Uint8Array<ArrayBuffer>;

function windowFor(v: SigningWindowVector, nowSec: () => number): Window | undefined {
	switch (v.window) {
		case "clock":
			return clockWindow(nowSec, v.ttl_sec);
		case "monotonic":
			return monotonicWindow(nowSec, v.ttl_sec);
		case "default":
			expect(v.ttl_sec, "a default row records the default TTL").toBe(MAX_SIGNATURE_LIFETIME);
			return undefined;
	}
	throw new Error(`unknown window kind ${v.window}`);
}

afterEach(() => {
	vi.useRealTimers();
});

describe("signing-window corpus", () => {
	it("records this SDK's MAX_SIGNATURE_LIFETIME", () => {
		expect(corpus.max_signature_lifetime_sec).toBe(MAX_SIGNATURE_LIFETIME);
	});

	it("is not empty", () => {
		expect(VECTORS.length).toBeGreaterThan(0);
	});

	for (const v of VECTORS) {
		it(v.name, async () => {
			vi.useFakeTimers({ toFake: ["Date"] });
			let nowMs = 0;
			const window = windowFor(v, () => nowMs / 1000);
			const { privKey, keyid, signatureAgent } = await genSigner();
			const { send: base, calls: sent } = capturingSend();
			const signing = createSigningTransport(base, {
				privKey,
				keyid,
				signatureAgent,
				...(window !== undefined ? { window } : {}),
			});
			expect(v.expected).toHaveLength(v.clock_ms.length);
			for (const [i, ms] of v.clock_ms.entries()) {
				nowMs = ms;
				vi.setSystemTime(ms);
				const want = v.expected[i] as Expectation;
				const before = sent.length;
				const send = signing(URL_, { method: "POST", headers: {}, body: BODY });
				if (want.expected_reason !== "") {
					await expect(send, `request ${i} at ${ms} ms`).rejects.toMatchObject({
						reason: want.expected_reason,
					});
					expect(sent, `request ${i}: a refused signature was sent`).toHaveLength(before);
					continue;
				}
				await send;
				expect(sent, `request ${i}: nothing was sent`).toHaveLength(before + 1);
				const input = sent[before]?.init.headers?.["signature-input"] ?? "";
				const m = /;created=(\d+);expires=(\d+)/.exec(input);
				expect(m, input).not.toBeNull();
				expect([Number(m?.[1]), Number(m?.[2])], `request ${i} at ${ms} ms`).toEqual([want.created, want.expires]);
			}
		}, 30_000);
	}
});
