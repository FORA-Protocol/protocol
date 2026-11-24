// sdk/ts Web Bot Auth -01 Signature-Agent parity against the shared Go oracle.
//
// The Go SDK reads and sends draft-ietf-webbotauth-httpsig-protocol-01 (WG-01)
// Signature-Agent values; wba-signature-agent-vectors.json records, for each wire value,
// the key directory URL and identity the Go verifier reads from it or the typed refusal it
// answers with, and what a signer configured with a value sends. This suite replays every
// row through the TypeScript faces: verifyRequestServer for the verdict, reason and
// Accept-Signature, signatureDirectory for the typed refusal, and createSigningTransport
// for the signer rows, whose sent request is verified again.
//
// The TypeScript reader still implements -00. The rows it does not meet yet are listed in
// PENDING_WBA_01 (wba01-pending.ts, the one list every replay reads), each with the WG-01
// rule it needs and the outcome the SDK produces today, as tests that MUST fail for that
// outcome only. An unlisted row that fails is a regression.

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import multisigVectors from "../../go/helpers/testdata/multisig-chain-vectors.json";
import popVectors from "../../go/helpers/testdata/pop-vectors.json";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
import acceptVerifyVectors from "../../go/helpers/testdata/verify-request-accept-vectors.json";
import corpus from "../../go/helpers/testdata/wba-signature-agent-vectors.json";
import { parseSignatureHeaders } from "../core/multisig-parse.ts";
import { createSigningTransport, type OutboundInit } from "../core/signing-transport.ts";
import { verifyRequestServer } from "../core/verify-request.ts";
import { signatureDirectory, WebBotAuthError } from "../core/wba.ts";
import { wbaDirectoryURL } from "../resolvers/documents.ts";
import {
	b64urlToBytes,
	directoryResolver,
	hexToBytes,
	memoryReplayStore,
	verifyVectorHeaders,
} from "./wba-fixtures.ts";
import {
	type Observe,
	PENDING_WBA_01,
	raisedOutcome,
	signOutcome,
	verifyOutcome,
	wba01It,
	wba01Owns,
} from "./wba01-pending.ts";

const CORPUS = "wba-signature-agent-vectors";

type VerifierRow = {
	name: string;
	method: string;
	url: string;
	body_hex: string;
	authorization: string;
	signature_agent: string;
	content_digest: string;
	signature_input: string;
	signature: string;
	keyid: string;
	resolver_keyid: string;
	resolver_pubkey_b64url: string;
	now: number;
	expected_reason: string;
	expected_accept_signature?: string;
	expected_signature_agent?: string;
	expected_key_directory?: string;
	expected_identity?: string;
	expected_refusal?: string;
	supersedes?: string;
	extra_headers?: Record<string, string>;
};

type SignerRow = {
	name: string;
	configured: string;
	signature_agent?: string;
	expected_key_directory?: string;
	expected_refusal?: string;
};

const doc = corpus as { draft: string; refusals: Record<string, string>; vectors: VerifierRow[]; signer: SignerRow[] };
const accept = new Map((acceptVerifyVectors as { vectors: VerifierRow[] }).vectors.map((v) => [v.name, v]));

// The corpus records the names the SDKs use. A WebBotAuthError reason is the token
// itself; a signatureDirectory refusal kind is the token without its
// "signature_agent_" prefix ("signature_agent_form" is kind "form", "missing_component"
// is kind "missing_component"), so no table maps them.
function refusalKind(token: string): string {
	return token.replace(/^signature_agent_/, "");
}

async function replayVerifier(v: VerifierRow, observe: Observe): Promise<void> {
	const keyid = v.resolver_keyid || v.keyid;
	const pub = b64urlToBytes(v.resolver_pubkey_b64url);
	const origin = v.expected_signature_agent ?? "";
	const resolver = directoryResolver([{ directory: origin, keyid, pub }]);
	const verdict = await verifyRequestServer({
		method: v.method,
		url: v.url,
		body: hexToBytes(v.body_hex),
		headers: verifyVectorHeaders(v),
		resolve: resolver,
		replayStore: memoryReplayStore(),
		now: () => v.now,
	});
	observe(verifyOutcome(verdict.valid, verdict.reason, verdict.acceptSignature));
	if (v.supersedes !== undefined) {
		// The -00 corpus row carries this exact request with the outcome WG-01 reverses.
		const [corpusName, name = ""] = v.supersedes.split("#");
		expect(corpusName).toBe("verify-request-accept-vectors");
		const old = accept.get(name);
		expect([old?.signature_agent, old?.signature_input, old?.signature]).toEqual([
			v.signature_agent,
			v.signature_input,
			v.signature,
		]);
	}
	const refusal = v.expected_refusal ?? "";
	if (refusal === "") {
		expect(verdict.valid, verdict.reason).toBe(true);
		expect(verdict.signatureAgent).toBe(origin);
		expect(resolver.calls).toEqual([[origin, keyid]]);
		const identity = new URL(origin).host;
		expect(identity).toBe(v.expected_identity);
		// Computed by this test from the verified origin, not read from the verdict: the
		// TypeScript verdict carries no key directory field until the port adds one.
		expect(wbaDirectoryURL("https", identity)).toBe(v.expected_key_directory);
		return;
	}
	expect(verdict.valid).toBe(false);
	expect(verdict.reason).toBe(v.expected_reason);
	expect(verdict.acceptSignature).toBe(v.expected_accept_signature);
	expect(resolver.calls).toEqual([]);
	// The typed refusal, through the directory rule the verifier applies.
	const parsed = parseSignatureHeaders(v.signature_input, v.signature);
	expect(parsed.ok).toBe(true);
	if (!parsed.ok) return;
	const sig = parsed.value[0];
	expect(sig).toBeDefined();
	if (sig === undefined) return;
	const joined = [v.signature_agent, ...Object.values(v.extra_headers ?? {})].join(", ");
	const named = signatureDirectory(joined, sig, parsed.value.length);
	expect(named.ok).toBe(false);
	if (named.ok) return;
	expect(named.refusal.kind).toBe(refusalKind(refusal));
}

const SIGNER_URL = "https://broker.example/fora.v1.BrokerService/Fetch";
const SIGNER_WINDOW: [number, number] = [1_700_000_000, 1_700_000_060];

async function replaySigner(v: SignerRow, observe: Observe): Promise<void> {
	const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const privKey = keys.privateKey;
	let sent: OutboundInit | undefined;
	const transport = createSigningTransport(
		async (_url: string, init: OutboundInit) => {
			sent = init;
		},
		{ privKey, keyid: "agent.v1", signatureAgent: v.configured, window: () => SIGNER_WINDOW },
	);
	const body = new TextEncoder().encode("{}") as Uint8Array<ArrayBuffer>;
	const refusal = v.expected_refusal ?? "";
	let thrown: unknown;
	try {
		await transport(SIGNER_URL, { method: "POST", headers: {}, body });
	} catch (err) {
		thrown = err;
	}
	const headers = sent?.headers ?? {};
	observe(thrown === undefined ? signOutcome(headers["signature-agent"]) : raisedOutcome(thrown));
	if (refusal !== "") {
		expect(thrown).toBeInstanceOf(WebBotAuthError);
		expect((thrown as WebBotAuthError).reason).toBe(refusal);
		expect(sent).toBeUndefined();
		return;
	}
	expect(thrown).toBeUndefined();
	expect(headers["signature-agent"]).toBe(v.signature_agent);
	// The request the transport sent verifies under the signer's key, in the directory
	// its member names: a signer that wrote the right header over another base fails here.
	const pub = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
	const verdict = await verifyRequestServer({
		method: "POST",
		url: SIGNER_URL,
		body,
		headers: {
			"content-digest": headers["content-digest"] ?? "",
			"signature-input": headers["signature-input"] ?? "",
			signature: headers.signature ?? "",
			authorization: headers.authorization ?? "",
			"signature-agent": headers["signature-agent"] ?? "",
		},
		resolve: { resolve: (keyid) => (keyid === "agent.v1" ? pub : undefined) },
		now: () => SIGNER_WINDOW[0] + 10,
	});
	expect(verdict.valid, verdict.reason).toBe(true);
	// Computed by this test from the verified origin, not read from the verdict: the
	// TypeScript verdict carries no key directory field until the port adds one.
	expect(wbaDirectoryURL("https", new URL(verdict.signatureAgent ?? "").host)).toBe(v.expected_key_directory);
}

describe("sdk/ts Signature-Agent reader and signer against the WG-01 Go oracle", () => {
	it("the corpus pins draft -01 and documents every refusal token it uses", () => {
		expect(doc.draft).toBe("draft-ietf-webbotauth-httpsig-protocol-01");
		const used = [...doc.vectors, ...doc.signer].flatMap((r) => (r.expected_refusal ? [r.expected_refusal] : []));
		for (const token of used) expect(Object.keys(doc.refusals)).toContain(token);
	});

	it("every pending entry names a corpus row and a face", () => {
		const names = (vs: Array<{ name: string }>) => vs.map((v) => v.name);
		const rowsOf: Record<string, Set<string>> = {
			[CORPUS]: new Set([...doc.vectors.map((v) => `vectors/${v.name}`), ...doc.signer.map((s) => `signer/${s.name}`)]),
			"sign-request-vectors": new Set(names((signRequestVectors as { vectors: Array<{ name: string }> }).vectors)),
			"pop-vectors": new Set(names(popVectors as Array<{ name: string }>)),
			"multisig-chain-vectors": new Set(names((multisigVectors as { vectors: Array<{ name: string }> }).vectors)),
		};
		for (const entry of Object.keys(PENDING_WBA_01)) {
			const [corpusName = "", rest = ""] = entry.split("#");
			const face = rest.slice(rest.lastIndexOf(":") + 1);
			const row = rest.slice(0, rest.lastIndexOf(":"));
			expect(["sign", "verify"], entry).toContain(face);
			expect(rowsOf[corpusName]?.has(row), entry).toBe(true);
		}
	});

	// vitest runs each file in its own module graph, so the check that every entry is
	// registered runs in the file that owns its (corpus, face) pair; this one checks that
	// every pair in the list has exactly one owner. An owner names its pair with string
	// literals, which is what this check reads.
	it("every (corpus, face) pair in the pending list is owned by exactly one test file", () => {
		const dir = fileURLToPath(new URL(".", import.meta.url));
		const owners = new Map<string, string[]>();
		for (const file of readdirSync(dir).filter((f) => f.endsWith(".test.ts"))) {
			for (const m of readFileSync(`${dir}${file}`, "utf8").matchAll(/wba01Owns\("([^"]+)", "(sign|verify)"\)/g)) {
				const pair = `${m[1]}:${m[2]}`;
				owners.set(pair, [...(owners.get(pair) ?? []), file]);
			}
		}
		const pairs = new Set(Object.keys(PENDING_WBA_01).map((k) => `${k.split("#")[0]}:${k.split(":").at(-1)}`));
		for (const pair of pairs) expect(owners.get(pair) ?? [], pair).toHaveLength(1);
	});

	for (const v of doc.vectors) {
		wba01It(CORPUS, `vectors/${v.name}`, "verify")(`vectors/${v.name}`, (observe) => replayVerifier(v, observe));
	}
	for (const s of doc.signer) {
		wba01It(CORPUS, `signer/${s.name}`, "sign")(`signer/${s.name}`, (observe) => replaySigner(s, observe));
	}
	wba01Owns("wba-signature-agent-vectors", "verify");
	wba01Owns("wba-signature-agent-vectors", "sign");
});
