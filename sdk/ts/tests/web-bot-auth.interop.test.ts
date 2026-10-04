// Interop with Cloudflare's web-bot-auth library, an independent implementation of the
// Web Bot Auth profile (draft-ietf-webbotauth-httpsig-protocol-00). The SDK's own
// vectors prove the three SDKs agree with each other; this proves they agree with a
// library none of them shares code with, in both directions:
//
//   (a) web-bot-auth's verify accepts a request signature and a delivery proof the TS
//       SDK signs;
//   (b) web-bot-auth's verify accepts the Go-emitted documented examples and the
//       delivery-proof vectors;
//   (c) the TS verifier accepts a signature web-bot-auth's sign makes once it is asked
//       to cover the components a FORA RPC requires.
//
// web-bot-auth requires the resolved verifier's keyid to equal the signature's keyid,
// and computes it as the RFC 7638 thumbprint, so every signature here names its key by
// thumbprint. It also requires a nonce to be 64 bytes in canonical encoding, so the SDK
// signatures carry the nonce the signing transport and the delivery client mint.

import { describe, expect, it } from "vitest";
import { sign, verify } from "web-bot-auth";
import { signerFromJWK, verifierFromJWK } from "web-bot-auth/crypto";

import { signInbound } from "../core/sign.ts";
import { contentDigest, signRequest } from "../core/sign-request.ts";
import { newNonce } from "../core/signing-transport.ts";
import { verifyRequestServer } from "../core/verify-request.ts";
import { thumbprint } from "../src/thumbprint.ts";
import popVectors from "../../go/helpers/testdata/pop-vectors.json";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
import { AGENT_DIRECTORY, b64urlToBytes, directoryResolver, hexToBytes } from "./wba-fixtures.ts";

const URL_ = "https://exchange.example/fora.v1.ExchangeService/DiscoverResources";
const CREATED = 1_790_812_801;
const BODY = new TextEncoder().encode('{"q":1}') as Uint8Array<ArrayBuffer>;

/** A fresh Ed25519 key, its public JWK, and its thumbprint keyid. */
async function agentKey(): Promise<{ keyPair: CryptoKeyPair; jwk: JsonWebKey; keyid: string }> {
	const keyPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
	const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, jwk, keyid: await thumbprint(raw) };
}

/** web-bot-auth's verify over `request`, resolving only `keyid` to the key `x` names. */
async function wbaVerify(request: Request, x: string, keyid: string, nowSec: number) {
	const verifier = await verifierFromJWK({ kty: "OKP", crv: "Ed25519", x });
	expect(verifier.keyid).toBe(keyid);
	return verify(request, {
		resolver: (candidate) => {
			if (candidate.keyid !== keyid) throw new Error(`unknown key ${candidate.keyid}`);
			return verifier;
		},
		now: new Date(nowSec * 1000),
		maxAge: 300,
	});
}

describe("web-bot-auth verifies what the TS SDK signs", () => {
	it("accepts a FORA RPC request signature", async () => {
		const { keyPair, jwk, keyid } = await agentKey();
		const signed = await signRequest(keyPair.privateKey, {
			method: "POST",
			url: URL_,
			body: BODY,
			authorization: "",
			signatureAgent: AGENT_DIRECTORY,
			keyid,
			created: CREATED,
			expires: CREATED + 300,
			nonce: newNonce(),
		});
		const request = new Request(URL_, {
			method: "POST",
			body: BODY,
			headers: {
				"content-digest": signed.contentDigest,
				authorization: signed.authorization,
				"signature-agent": signed.signatureAgent,
				"signature-input": signed.signatureInput,
				signature: signed.signature,
			},
		});
		const verified = await wbaVerify(request, jwk.x ?? "", keyid, CREATED + 10);
		expect(verified.keyid).toBe(keyid);
		expect(verified.tag).toBe("web-bot-auth");
	});

	it("accepts a delivery proof", async () => {
		const { keyPair, jwk, keyid } = await agentKey();
		const url = `https://cdn.example/doc?agent_id=${keyid}`;
		const proof = await signInbound(keyPair, url, {
			signatureAgent: AGENT_DIRECTORY,
			nonce: newNonce(),
			window: () => [CREATED, CREATED + 300],
		});
		const verified = await wbaVerify(proof, jwk.x ?? "", keyid, CREATED + 10);
		expect(verified.keyid).toBe(keyid);
	});
});

describe("web-bot-auth verifies the Go-emitted vectors", () => {
	type SignVector = (typeof signRequestVectors.vectors)[number];
	for (const name of ["doc_single_hop_example", "doc_broker_example"]) {
		it(`accepts the sign-request vector ${name}`, async () => {
			const v = signRequestVectors.vectors.find((x) => x.name === name) as SignVector;
			const headers = new Headers();
			for (const [k, values] of Object.entries(v.emitted_headers)) for (const x of values) headers.append(k, x);
			const request = new Request(v.url, { method: v.method, headers, body: hexToBytes(v.body_hex) });
			await wbaVerify(request, v.pubkey_b64url, v.keyid, Math.floor((v.created + v.expires) / 2));
		});
	}

	type PopVector = (typeof popVectors)[number];
	for (const name of ["valid", "valid_no_nonce"]) {
		it(`accepts the delivery-proof vector ${name}`, async () => {
			const v = popVectors.find((x) => x.name === name) as PopVector;
			const request = new Request(v.url, {
				method: "GET",
				headers: { "signature-agent": v.signature_agent, "signature-input": v.signature_input, signature: v.signature },
			});
			await wbaVerify(request, v.presented_key_b64url, v.agent_id, v.now_unix);
		});
	}
});

describe("the TS verifier accepts what web-bot-auth signs", () => {
	it("accepts a web-bot-auth signature covering the FORA RPC components", async () => {
		const { jwk, keyid } = await agentKey();
		const digest = await contentDigest(BODY);
		const request = new Request(URL_, {
			method: "POST",
			body: BODY,
			headers: { "signature-agent": `sig1="${AGENT_DIRECTORY}"`, "content-digest": digest, authorization: "" },
		});
		const fields = await sign(request, {
			signer: await signerFromJWK(jwk),
			created: new Date(CREATED * 1000),
			expires: new Date((CREATED + 240) * 1000),
			target: "@target-uri",
			additionalComponents: ["@method", "content-digest", "authorization"],
		});
		const verdict = await verifyRequestServer({
			method: "POST",
			url: URL_,
			body: BODY,
			headers: {
				"content-digest": digest,
				authorization: "",
				"signature-agent": `sig1="${AGENT_DIRECTORY}"`,
				"signature-input": fields.signatureInput,
				signature: fields.signature,
			},
			resolve: directoryResolver([{ directory: AGENT_DIRECTORY, keyid, pub: b64urlToBytes(jwk.x ?? "") }]),
			now: () => CREATED + 10,
		});
		expect(verdict).toEqual({ valid: true, keyid, signatureAgent: AGENT_DIRECTORY });
	});
});
