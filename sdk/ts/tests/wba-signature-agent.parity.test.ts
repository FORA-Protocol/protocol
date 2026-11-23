// sdk/ts Web Bot Auth -01 Signature-Agent parity against the shared Go oracle.
//
// The Go SDK reads and sends draft-ietf-webbotauth-httpsig-protocol-01 Signature-Agent
// values; wba-signature-agent-vectors.json records, for each wire value, the key
// directory URL and identity the Go verifier reads from it or the typed refusal it
// answers with, and what a signer configured with a value sends. This suite replays
// every row through the TypeScript faces: verifyRequestServer for the verdict, reason
// and Accept-Signature, signatureDirectory for the typed refusal, and
// createSigningTransport for the signer rows.
//
// The TypeScript reader still implements -00. The rows it does not meet yet are listed in
// PENDING_WBA_01, each with the -01 rule it needs, as tests that MUST fail (it.fails): a
// listed row that starts to pass fails the suite, so the port removes its entry in the
// same change, and an unlisted row that fails is a regression. A listed row counts as
// failing only on an assertion, the way pytest's raises=AssertionError does, so a replay
// that breaks for another reason is not mistaken for a pending -01 rule.

import { describe, expect, it } from "vitest";
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
	importSigningKey,
	memoryReplayStore,
	verifyVectorHeaders,
} from "./wba-fixtures.ts";

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

const WELL_KNOWN = "a member naming the well-known key directory URL names that directory (-01 §5.5)";
const PARAMETER = "a member with a parameter is ignored (-01 §5.2.1), so the signature names no directory";
const OTHER_URL = "another path, a query or a fragment is refused with refusal kind not_key_directory";
const SIGN_COMPLETES = "a signer completes a configured origin to its well-known key directory URL (-01 §5.2.1)";
const SIGN_URL = "a signer accepts the well-known key directory URL as its configured value";
const SIGN_OTHER_URL = "a signer refuses another path, a query or a fragment as signature_agent_not_key_directory";

// The rows the -00 TypeScript reader and signer do not meet yet. The port deletes each
// entry as the rule it names lands; a listed row that passes fails the suite.
const PENDING_WBA_01: Record<string, string> = {
	"vectors:well_known_url": WELL_KNOWN,
	"vectors:well_known_url_with_port": WELL_KNOWN,
	"vectors:legacy_string_well_known_url": WELL_KNOWN,
	"vectors:member_key_differs_from_label": WELL_KNOWN,
	"vectors:repeated_field_lines_member_on_first": WELL_KNOWN,
	"vectors:repeated_field_lines_member_on_second": WELL_KNOWN,
	"vectors:escaped_quote_in_another_member": WELL_KNOWN,
	"vectors:ignored_member_beside_the_signers": WELL_KNOWN,
	"vectors:member_with_parameter": PARAMETER,
	"vectors:member_type_directory_string": PARAMETER,
	"vectors:member_type_directory_token": PARAMETER,
	"vectors:member_with_other_parameter": PARAMETER,
	"vectors:legacy_string_with_parameter": PARAMETER,
	"vectors:repeated_field_lines_member_with_parameter": PARAMETER,
	"vectors:other_path": OTHER_URL,
	"vectors:origin_with_trailing_slash": OTHER_URL,
	"vectors:well_known_path_with_trailing_slash": OTHER_URL,
	"vectors:well_known_path_in_another_case": OTHER_URL,
	"vectors:query": OTHER_URL,
	"vectors:bare_origin_with_query": OTHER_URL,
	"vectors:fragment": OTHER_URL,
	"vectors:escaped_quote_in_the_covered_value": OTHER_URL,
	"signer:origin_completed": SIGN_COMPLETES,
	"signer:well_known_url_as_given": SIGN_URL,
	"signer:origin_with_port_completed": SIGN_COMPLETES,
	"signer:other_path": SIGN_OTHER_URL,
	"signer:query": SIGN_OTHER_URL,
	"signer:fragment": SIGN_OTHER_URL,
};

// Each refusal token, as the TypeScript reader names it: the signatureDirectory refusal
// kind and the WebBotAuthError reason a signer throws. The -01 names are the ones the
// port gives them.
const TS_KIND: Record<string, string> = {
	member_ignored: "ignored",
	not_key_directory: "not_key_directory",
	not_https_origin: "not_origin",
	form: "form",
	missing_component: "missing_component",
};
const TS_SIGN_REASON: Record<string, string> = {
	required: "signature_agent_required",
	not_https_origin: "signature_agent_not_origin",
	not_key_directory: "signature_agent_not_key_directory",
};

async function replayVerifier(v: VerifierRow): Promise<void> {
	if (v.supersedes !== undefined) {
		// The -00 corpus row carries this exact request with the outcome -01 reverses.
		const old = accept.get(v.supersedes.split("#")[1] ?? "");
		expect([old?.signature_agent, old?.signature_input, old?.signature]).toEqual([
			v.signature_agent,
			v.signature_input,
			v.signature,
		]);
	}
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
	const refusal = v.expected_refusal ?? "";
	if (refusal === "") {
		expect(verdict.valid, verdict.reason).toBe(true);
		expect(verdict.signatureAgent).toBe(origin);
		expect(resolver.calls).toEqual([[origin, keyid]]);
		const identity = new URL(origin).host;
		expect(identity).toBe(v.expected_identity);
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
	expect(named.refusal.kind).toBe(TS_KIND[refusal]);
}

const SEED = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

async function replaySigner(v: SignerRow): Promise<void> {
	const privKey = await importSigningKey(SEED);
	let sent: OutboundInit | undefined;
	const transport = createSigningTransport(
		async (_url: string, init: OutboundInit) => {
			sent = init;
		},
		{ privKey, keyid: "agent.v1", signatureAgent: v.configured, window: () => [1_700_000_000, 1_700_000_060] },
	);
	const body = new TextEncoder().encode("{}") as Uint8Array<ArrayBuffer>;
	const refusal = v.expected_refusal ?? "";
	let thrown: unknown;
	try {
		await transport("https://broker.example/fora.v1.BrokerService/Fetch", { method: "POST", headers: {}, body });
	} catch (err) {
		thrown = err;
	}
	if (refusal !== "") {
		expect(thrown).toBeInstanceOf(WebBotAuthError);
		expect((thrown as WebBotAuthError).reason).toBe(TS_SIGN_REASON[refusal]);
		expect(sent).toBeUndefined();
		return;
	}
	expect(thrown).toBeUndefined();
	const agent = sent?.headers?.["signature-agent"];
	expect(agent).toBe(v.signature_agent);
	// The member value, read back as the origin a -00 reader reports, names the
	// recorded key directory.
	const dict = agent?.match(/^sig1="([^"]*)"$/)?.[1] ?? "";
	expect(wbaDirectoryURL("https", new URL(dict).host)).toBe(v.expected_key_directory);
}

// isAssertion tells an assertion failure from any other error, so a pending row counts
// as failing only on an assertion.
function isAssertion(err: unknown): boolean {
	return err instanceof Error && err.name === "AssertionError";
}

// pendingOrNot registers a row: an ordinary test, or, for a pending row, a test that
// must fail on an assertion. A pending replay that throws anything else returns
// normally, which it.fails reports as a failure.
function pendingOrNot(id: string, replay: () => Promise<void>): void {
	const reason = PENDING_WBA_01[id];
	if (reason === undefined) {
		it(id, replay);
		return;
	}
	it.fails(`${id} (pending -01: ${reason})`, async () => {
		try {
			await replay();
		} catch (err) {
			if (isAssertion(err)) throw err;
		}
	});
}

describe("sdk/ts Signature-Agent reader and signer against the Web Bot Auth -01 Go oracle", () => {
	it("the corpus pins draft -01 and documents every refusal token", () => {
		expect(doc.draft).toBe("draft-ietf-webbotauth-httpsig-protocol-01");
		expect(Object.keys(doc.refusals).sort()).toEqual([...Object.keys(TS_KIND), "required"].sort());
	});

	it("every pending entry names a row the corpus carries", () => {
		const ids = new Set([...doc.vectors.map((v) => `vectors:${v.name}`), ...doc.signer.map((s) => `signer:${s.name}`)]);
		for (const id of Object.keys(PENDING_WBA_01)) expect(ids.has(id), id).toBe(true);
	});

	for (const v of doc.vectors) pendingOrNot(`vectors:${v.name}`, () => replayVerifier(v));
	for (const s of doc.signer) pendingOrNot(`signer:${s.name}`, () => replaySigner(s));
});
