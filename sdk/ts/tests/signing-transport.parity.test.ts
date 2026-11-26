// sdk/ts SigningTransport / signOutbound outbound auto-sign parity + behavior.
//
// The TS sibling of Go core.NewSigningTransport + SigningOption and Python
// SigningTransport / SignedOutbound:
//   - signOutbound({ privKey, keyid, method, url, body, authorization,
//     signatureAgent, window, appendOnly, coverPrevious, prior? }) -> { headers, body }
//     (transport-neutral header core, Python SignedOutbound sibling);
//   - createSigningTransport(send, opts) -> a WHATWG-fetch-shaped send that buffers
//     the body, stamps the RFC 9421 headers via signOutbound, and forwards the SAME
//     body bytes to the wrapped send.
//
// Core invariant: the transport is a pure ORCHESTRATION of
// the already-parity-locked signRequest / appendSignature + clockWindow
// primitives — it stamps RFC 9421 headers byte-identical to the
// shared Go/Python oracle, forwards the request body UNMODIFIED, and adds NO new
// crypto and NO new signature-base rendering.
//
// Proof strategy (corpus-first, no new emitter): replay the SAME shared Go vectors
// the primitive suites already verify against
// (sdk/go/helpers/testdata/sign-request-vectors.json for the fresh-sig and
// append paths, multisig-chain-vectors.json for a second signer) THROUGH the
// transport via a capturing fake send, and assert the stamped headers equal the
// vector fields byte-for-byte. Each vector injects a FIXED window
// ()=>[v.created, v.expires] — the DEFAULT clockWindow(now) drifts created/expires
// and the base would not reproduce; the windowless sign-request.parity.test.ts
// harness is adapted, NOT copied verbatim. The option-behavior legs, which pin the
// transport's plumbing rather than byte-parity, are in signing-transport.options.test.ts.

import { stdBase64 } from "@fora-protocol/sdk-l1/base64url";
import { describe, expect, it } from "vitest";
import multisigVectors from "../../go/helpers/testdata/multisig-chain-vectors.json";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
// The append path reuses the already-landed primitives to arrange the upstream sig1
// state the second signer's transport appends to.
import { signRequest } from "../core/sign-request.ts";
import { createSigningTransport, signOutbound } from "../core/signing-transport.ts";
// Use the EXPORTED header constant (do NOT string-literal "signature-agent").
import { SignatureAgentHeader } from "../src/wire.ts";
import { rowNamed } from "./harness/corpus.ts";
import { bytesEqual, hexToBytes, importSigningKey } from "./harness/keys.ts";
import {
	type Captured,
	capturingSend,
	type MultisigChainVector,
	type MultisigHop,
	SIGNATURE_AGENT_EMITTED,
} from "./harness/requests.ts";

// ---------------------------------------------------------------------------
// Vector shapes (shared Go emitter output — the sole oracle).
// ---------------------------------------------------------------------------

type SignRequestVector = {
	name: string;
	method: string;
	url: string;
	body_hex: string;
	authorization: string;
	/** The key-directory ORIGIN the signer was given. */
	signature_agent: string;
	append_only?: boolean;
	keyid: string;
	created: number;
	expires: number;
	/** RFC 9421 nonce the oracle signed with; absent when it signed without one. */
	nonce?: string;
	signer_seed_hex: string;
	content_digest: string;
	signature_input: string;
	signature: string;
	/** What the SIGNER puts on a bare request — what is SENT, as against every other
	 * field here, which records what was SIGNED. A LIST per name because that is what
	 * the verifier reads: it joins repeated values with ", " before rebuilding the base. */
	emitted_headers: Record<string, string[]>;
};

/** This face returns one value per name and cannot hold a duplicate, so each wraps to a
 * one-element list. The keys are compared VERBATIM: normalizing the casing here is what
 * previously hid a signed key spelled differently from the one a caller supplies, which
 * puts two field lines on the wire and breaks the rebuilt base. */
function asEmitted(h: Record<string, string>): Record<string, string[]> {
	return Object.fromEntries(Object.entries(h).map(([k, v]) => [k, [v]]));
}

// Asserts what the transport forwarded for one sign-request vector: (a) the stamped
// RFC 9421 artifacts equal the Go oracle, (c) one field line per covered name, and
// (b) the body forwarded unmodified.
async function expectForwardedAsVector(fwd: Captured, v: SignRequestVector, body: Uint8Array): Promise<void> {
	const h = fwd.init.headers ?? {};

	// (a) PARITY: the stamped RFC 9421 artifacts equal the Go oracle fields.
	expect(h["content-digest"]).toBe(v.content_digest);
	expect(h["signature-input"]).toBe(v.signature_input);
	expect(h.signature).toBe(v.signature);

	// (c) ONE FIELD LINE PER COVERED NAME. Header names are case-insensitive on the
	// wire and JS object keys are not, so a caller's spelling surviving beside the
	// signed one puts the name on the wire twice; the verifier joins repeated values
	// with ", " before rebuilding the base, and a correct signature is then refused.
	// Asserted over the WHOLE forwarded map — the emitted set is what the corpus
	// records, and the caller's differently-cased key must be gone from it.
	const names = Object.keys(h).map((k) => k.toLowerCase());
	expect(new Set(names).size, `duplicated header names: ${names}`).toBe(names.length);
	expect(asEmitted(h)).toEqual(v.emitted_headers);

	// (b) BODY-INTEGRITY (the key regression guard): the FORWARDED body bytes
	// must equal the input body. A wrapper that buffers-for-digest but forwards
	// a consumed/empty body would still stamp a correct header and ship green —
	// so assert the body itself, not only the header.
	expect(bytesEqual(fwd.init.body, body)).toBe(true);
	// Recompute the digest over the FORWARDED body to double-lock (b): a body
	// swap that preserved length would still be caught here.
	const fwdDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", fwd.init.body ?? new Uint8Array()));
	expect(h["content-digest"]).toBe(`sha-256=:${stdBase64(fwdDigest)}:`);
}

// ---------------------------------------------------------------------------
// (a)+(b) PARITY + BODY-INTEGRITY through the transport.
// ---------------------------------------------------------------------------

describe("createSigningTransport replays the shared Go sign-request vectors byte-identically", () => {
	const doc = signRequestVectors as { vectors: SignRequestVector[] };

	it("vector matrix is non-empty and every vector names a directory origin", () => {
		expect(doc.vectors.length).toBeGreaterThan(0);
		for (const v of doc.vectors) expect(v.signature_agent).toMatch(/^https:\/\//);
	});

	// The transport refuses to sign without a nonce, so it replays only the
	// vectors signed with one; the signRequest parity tests replay every vector.
	for (const v of doc.vectors.filter((x) => x.nonce !== undefined)) {
		it(`${v.name}: transport stamps Content-Digest/Signature-Input/Signature === Go oracle AND forwards the body unmodified`, async () => {
			const { send, calls } = capturingSend();
			const priv = await importSigningKey(v.signer_seed_hex);

			// FIXED window per vector: reproduce the vector's created/expires;
			// the default clockWindow(now) would drift the base.
			const signing = createSigningTransport(send, {
				privKey: priv,
				keyid: v.keyid,
				window: () => [v.created, v.expires] as [number, number],
				// The transport mints a random nonce per signature; pin it to the vector's.
				nonce: () => v.nonce ?? "",
				signatureAgent: v.signature_agent,
				appendOnly: v.append_only ?? false,
			});

			const body = hexToBytes(v.body_hex);
			await signing(v.url, {
				method: v.method,
				// Spelled the CONVENTIONAL HTTP way, deliberately differing in case from the
				// lowercase key the signer emits. Every test here used to pass the one spelling
				// that cannot collide, which is why a signed key landing BESIDE a caller's rather
				// than replacing it went unseen through a whole green suite.
				headers: { Authorization: v.authorization },
				body,
			});

			expect(calls.length).toBe(1);
			await expectForwardedAsVector(calls[0] as Captured, v, body);
		});
	}
});

// ---------------------------------------------------------------------------
// signOutbound — the transport-neutral header core (Python SignedOutbound
// sibling). Same vectors, asserted directly on the returned {headers, body}.
// ---------------------------------------------------------------------------

describe("signOutbound returns the RFC 9421 header set byte-identical to the Go oracle", () => {
	const doc = signRequestVectors as { vectors: SignRequestVector[] };

	// The transport refuses to sign without a nonce, so it replays only the
	// vectors signed with one; the signRequest parity tests replay every vector.
	for (const v of doc.vectors.filter((x) => x.nonce !== undefined)) {
		it(`${v.name}: header core matches the oracle and returns the body unchanged`, async () => {
			const priv = await importSigningKey(v.signer_seed_hex);
			const body = hexToBytes(v.body_hex);
			const out = await signOutbound({
				privKey: priv,
				keyid: v.keyid,
				method: v.method,
				url: v.url,
				body,
				authorization: v.authorization,
				signatureAgent: v.signature_agent,
				window: () => [v.created, v.expires] as [number, number],
				nonce: () => v.nonce ?? "",
				appendOnly: v.append_only ?? false,
			});

			expect(out.headers["content-digest"]).toBe(v.content_digest);
			expect(out.headers["signature-input"]).toBe(v.signature_input);
			expect(out.headers.signature).toBe(v.signature);

			// The WHOLE emitted set, compared as a map rather than key by key.
			//
			// Every assertion above says what was SIGNED; emitted_headers says what is
			// SENT, and the two are different claims. A verifier rebuilds the base from
			// the request it received, so a covered value bound but never sent is not
			// bound: it reads the covered names off signature-input, finds nothing under
			// one of them, and refuses. A port that bound authorization and signature-agent
			// and attached neither matched the oracle byte-for-byte on all three fields above
			// and could not complete a single signed call.
			//
			// Membership assertions are what let that ship. A map comparison is what
			// notices the next header to go missing.
			expect(asEmitted(out.headers)).toEqual(v.emitted_headers);

			// Transport-neutral core forwards the body untouched.
			expect(bytesEqual(out.body, body)).toBe(true);
		});
	}
});

// ---------------------------------------------------------------------------
// (c) APPEND path — a second signer adds its own member beside the agent's, which
// stays byte-for-byte untouched, and reproduces the Go two-signature vectors.
// ---------------------------------------------------------------------------

describe("createSigningTransport append path mirrors the Go multi-signature vectors", () => {
	const doc = multisigVectors as { vectors: MultisigChainVector[] };

	// The transport refuses to sign without a nonce, so only the vector whose hops were
	// signed with one is replayed through it.
	for (const name of ["positive_covering_two_nonce"]) {
		it(`${name}: the second signer's appendOnly transport reproduces the Go headers`, async () => {
			const v = rowNamed(doc.vectors, name);
			const h1 = v.hops[0] as MultisigHop;
			const h2 = v.hops[1] as MultisigHop;
			const body = hexToBytes(v.body_hex);

			// Arrange the incoming request state: the agent's sig1 and its member.
			const sig1 = await signRequest(await importSigningKey(h1.seed_hex), {
				method: v.method,
				url: v.url,
				body,
				authorization: v.authorization,
				signatureAgent: h1.directory,
				keyid: h1.keyid,
				created: v.created,
				expires: v.expires,
				nonce: h1.nonce ?? "",
			});

			const { send, calls } = capturingSend();
			const signing = createSigningTransport(send, {
				privKey: await importSigningKey(h2.seed_hex),
				keyid: h2.keyid,
				window: () => [v.created, v.expires] as [number, number],
				nonce: () => h2.nonce ?? "",
				appendOnly: true,
				coverPrevious: h2.cover_previous ?? false,
				signatureAgent: h2.directory,
			});

			await signing(v.url, {
				method: v.method,
				headers: {
					authorization: v.authorization,
					[SignatureAgentHeader]: sig1.signatureAgent,
					"content-digest": sig1.contentDigest,
					"signature-input": sig1.signatureInput,
					signature: sig1.signature,
				},
				body,
			});

			expect(calls.length).toBe(1);
			const fwd = calls[0] as Captured;
			const h = fwd.init.headers ?? {};
			// The agent's member is untouched and the second signer's is appended beside it.
			expect(h[SIGNATURE_AGENT_EMITTED]).toBe(v.signature_agent);
			expect(h["signature-input"]).toBe(v.signature_input);
			expect(h.signature).toBe(v.signature);
			expect(bytesEqual(fwd.init.body, body)).toBe(true);
		});
	}
});
