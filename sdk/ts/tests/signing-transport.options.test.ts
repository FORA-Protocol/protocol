// sdk/ts createSigningTransport option behavior, ported from
// sdk/go/core/transport_options_test.go. These tests pin the transport's plumbing
// (window, nonce, append path, coverPrevious, directory, signer source, sign predicate,
// defaults and the no-body pass-through), not byte-parity, so a freshly generated signer
// is used. The byte-parity replays of the shared Go vectors are in
// signing-transport.parity.test.ts.

import { utf8Bytes } from "@fora-protocol/sdk-l1/base64url";
import { describe, expect, it } from "vitest";
import { signRequest } from "../core/sign-request.ts";
import { createSigningTransport, type OutboundInit, type SignerSource } from "../core/signing-transport.ts";
import { WebBotAuthError } from "../core/wba.ts";
// Use the EXPORTED header constant (do NOT string-literal "signature-agent").
import { SignatureAgentHeader } from "../src/wire.ts";
import { b64urlToBytes, bytesEqual, genSigner as genTestSigner } from "./harness/keys.ts";
import { type Captured, capturingSend, SIGNATURE_AGENT_EMITTED } from "./harness/requests.ts";

// The key-directory origin the option-behavior transports sign as.
const TEST_DIR = "https://agent.example.com";

// The option-behavior legs pin plumbing (window/append/predicate/directory), not
// byte-parity, so they sign with a generated key under TEST_DIR.
const genSigner = () => genTestSigner(TEST_DIR);

const BODY = utf8Bytes('{"test":true}');

/** Sends one bodied POST with no headers of its own through signing, and returns the
 * headers the base send received. */
async function postOnce(
	signing: (url: string, init: OutboundInit) => Promise<unknown>,
	calls: Captured[],
	url: string,
): Promise<Record<string, string>> {
	await signing(url, { method: "POST", headers: {}, body: BODY });
	return (calls[0] as Captured).init.headers ?? {};
}

describe("createSigningTransport window and nonce", () => {
	it("WithWindow: injects the supplied created/expires into Signature-Input", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, {
			...(await genSigner()),
			window: () => [1_700_000_000, 1_700_000_300] as [number, number],
		});

		const sigInput = (
			await postOnce(signing, calls, "https://exchange.example.com/fora.exchange.v1.ExchangeService/DiscoverResources")
		)["signature-input"];
		expect(sigInput).toBeDefined();
		expect(sigInput).toContain("created=1700000000");
		expect(sigInput).toContain("expires=1700000300");
	});

	it("refuses a window longer than MAX_SIGNATURE_LIFETIME and sends nothing", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, {
			...(await genSigner()),
			window: () => [1_700_000_000, 1_700_000_600] as [number, number],
		});
		await expect(
			signing("https://exchange.example.com/fora.x/Y", { method: "POST", headers: {}, body: BODY }),
		).rejects.toMatchObject({ reason: "signature_lifetime" });
		expect(calls).toHaveLength(0);
	});

	it("each signature carries a fresh 64-byte nonce", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, await genSigner());
		await signing("https://exchange.example.com/fora.x/Y", { method: "POST", headers: {}, body: BODY });
		const input = (calls[0] as Captured).init.headers?.["signature-input"] ?? "";
		const nonce = /;nonce="([^"]*)"/.exec(input)?.[1] ?? "";
		expect(nonce).toHaveLength(86);
		expect(b64urlToBytes(nonce)).toHaveLength(64);
	});
});

describe("createSigningTransport append path", () => {
	it("appendOnly on a FRESH request still produces a valid sig1", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, { ...(await genSigner()), appendOnly: true });

		const sigInput = (await postOnce(signing, calls, "https://exchange.example.com/fora.x/Y"))["signature-input"] ?? "";
		expect(sigInput).toContain("sig1=");
		expect(sigInput).not.toContain("sig2=");
	});

	it("a request already carrying a Signature gets a second signature (sig2), never a replacement", async () => {
		// Prior-detection branch (Go sign(): appendOnly || req has Signature) — even
		// WITHOUT appendOnly, an incoming Signature selects the append path.
		const upstream = await genSigner();
		const sig1 = await signRequest(upstream.privKey, {
			method: "POST",
			url: "https://exchange.example.com/fora.x/Y",
			body: BODY,
			authorization: "",
			signatureAgent: upstream.signatureAgent,
			keyid: upstream.keyid,
			created: 1_700_000_000,
			expires: 1_700_000_300,
		});

		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, {
			...(await genSigner()),
			signatureAgent: "https://broker.example.com",
		}); // no appendOnly

		await signing("https://exchange.example.com/fora.x/Y", {
			method: "POST",
			headers: {
				"content-digest": sig1.contentDigest,
				[SignatureAgentHeader]: sig1.signatureAgent,
				"signature-input": sig1.signatureInput,
				signature: sig1.signature,
			},
			body: BODY,
		});

		const h = (calls[0] as Captured).init.headers ?? {};
		expect(h["signature-input"]).toContain("sig1=");
		expect(h["signature-input"]).toContain("sig2=");
		expect(h.signature).toContain("sig1=");
		expect(h.signature).toContain("sig2=");
		expect(h[SIGNATURE_AGENT_EMITTED]).toBe(`sig1="${TEST_DIR}", sig2="https://broker.example.com"`);
		// Without coverPrevious the second signature covers only its own request and member.
		expect(h["signature-input"]?.split("sig2=")[1]).not.toContain('"signature";key=');
	});
});

describe("createSigningTransport coverPrevious", () => {
	it("coverPrevious: an appended signature covers the earlier one completely", async () => {
		const agent = await genSigner();
		const first = capturingSend();
		await createSigningTransport(first.send, agent)("https://exchange.example.com/fora.x/Y", {
			method: "POST",
			headers: {},
			body: BODY,
		});
		const signedHeaders = (first.calls[0] as Captured).init.headers ?? {};

		const { send, calls } = capturingSend();
		const forwarder = createSigningTransport(send, {
			...(await genSigner()),
			signatureAgent: "https://relay.example.com",
			appendOnly: true,
			coverPrevious: true,
		});
		await forwarder("https://exchange.example.com/fora.x/Y", { method: "POST", headers: signedHeaders, body: BODY });

		const sig2 = (calls[0] as Captured).init.headers?.["signature-input"]?.split("sig2=")[1] ?? "";
		for (const want of ['"signature";key="sig1"', '"signature-input";key="sig1"', '"signature-agent";key="sig1"']) {
			expect(sig2).toContain(want);
		}
	});
});

describe("createSigningTransport signatureAgent directory", () => {
	it("signatureAgent: the directory becomes the signature's own covered member", async () => {
		const dir = "https://broker.example.com";
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, { ...(await genSigner()), signatureAgent: dir });

		const h = await postOnce(signing, calls, "https://exchange.example.com/fora.x/Y");
		expect(h[SIGNATURE_AGENT_EMITTED]).toBe(`sig1="${dir}"`);
		expect(h["signature-input"]).toContain('"signature-agent";key="sig1"');
		expect(h["signature-input"]).toContain('tag="web-bot-auth"');
	});

	it("signatureAgent: an incoming Signature-Agent with no signature is replaced, not kept", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, await genSigner());

		await signing("https://exchange.example.com/fora.x/Y", {
			method: "POST",
			headers: { [SignatureAgentHeader]: 'sig1="https://other.example"' },
			body: BODY,
		});

		const h = (calls[0] as Captured).init.headers ?? {};
		expect(h[SIGNATURE_AGENT_EMITTED]).toBe(`sig1="${TEST_DIR}"`);
		expect(Object.keys(h).filter((k) => k.toLowerCase() === "signature-agent")).toHaveLength(1);
	});

	it("refuses to sign without a directory, or with one that is not an https origin, and sends nothing", async () => {
		const { privKey, keyid } = await genSigner();
		for (const signatureAgent of [undefined, "http://agent.example.com", "https://agent.example.com/keys"]) {
			const { send, calls } = capturingSend();
			const signing = createSigningTransport(send, {
				privKey,
				keyid,
				...(signatureAgent !== undefined ? { signatureAgent } : {}),
			});
			const err = await signing("https://exchange.example.com/fora.x/Y", {
				method: "POST",
				headers: {},
				body: BODY,
			}).catch((e: unknown) => e);
			expect(err, String(signatureAgent)).toBeInstanceOf(WebBotAuthError);
			expect(calls).toHaveLength(0);
		}
	});
});

describe("createSigningTransport signerSource", () => {
	it("signerSource: signs as the source's identity, distinct signatures for identical requests in one second", async () => {
		const { privKey, keyid } = await genSigner();
		const source: SignerSource = (req) => ({
			privKey,
			keyid,
			signatureAgent: `https://${req.headers["x-tenant"]}.agents.example`,
		});
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, {
			signerSource: source,
			window: () => [1_700_000_000, 1_700_000_060] as [number, number],
		});
		for (let i = 0; i < 2; i += 1) {
			await signing("https://exchange.example.com/fora.x/Y", {
				method: "POST",
				headers: { "x-tenant": "alice" },
				body: BODY,
			});
		}
		const [a, b] = calls.map((c) => c.init.headers ?? {});
		expect(a?.[SIGNATURE_AGENT_EMITTED]).toBe('sig1="https://alice.agents.example"');
		expect(a?.["signature-input"]).toContain(`keyid="${keyid}"`);
		expect(a?.signature).not.toBe(b?.signature);
	});

	it("signerSource: an error or no signer sends nothing", async () => {
		const sources: SignerSource[] = [
			() => {
				throw new Error("no identity for this caller");
			},
			() => undefined,
		];
		for (const signerSource of sources) {
			const { send, calls } = capturingSend();
			const signing = createSigningTransport(send, { signerSource });
			await expect(
				signing("https://exchange.example.com/fora.x/Y", { method: "POST", headers: {}, body: BODY }),
			).rejects.toThrow();
			expect(calls).toHaveLength(0);
		}
	});
});

describe("createSigningTransport sign predicate", () => {
	it("predicate returning FALSE: request passes through UNSIGNED (not an error)", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, {
			...(await genSigner()),
			predicate: () => false,
		});

		const h = await postOnce(
			signing,
			calls,
			"https://exchange.example.com/fora.exchange.v1.ExchangeService/DiscoverResources",
		);
		expect(h["signature-input"]).toBeUndefined();
		// Pass-through still forwards the body untouched.
		expect(bytesEqual((calls[0] as Captured).init.body, BODY)).toBe(true);
	});

	it("predicate returning TRUE: signs even a non-/fora path", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, {
			...(await genSigner()),
			predicate: () => true,
		});

		const h = await postOnce(signing, calls, "https://exchange.example.com/other.service/Method");
		expect(h["signature-input"]).toBeDefined();
	});
});

describe("createSigningTransport defaults", () => {
	it("default (only the identity): signs any bodied request", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, await genSigner());

		const h = await postOnce(signing, calls, "https://exchange.example.com/fora.x/Y");
		expect(h["signature-input"]).toBeDefined();
		expect(h["content-digest"]).toBeDefined();
	});

	it("no-body request: passes through UNSIGNED (nothing to bind Content-Digest to)", async () => {
		const { send, calls } = capturingSend();
		const signing = createSigningTransport(send, await genSigner());

		await signing("https://exchange.example.com/fora.x/Y", {
			method: "GET",
			headers: {},
		});

		const h = (calls[0] as Captured).init.headers ?? {};
		expect(h["signature-input"]).toBeUndefined();
		expect(h["content-digest"]).toBeUndefined();
		expect((calls[0] as Captured).init.body).toBeUndefined();
	});
});
