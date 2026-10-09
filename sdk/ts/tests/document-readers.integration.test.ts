// The public document readers, driven against a real in-process origin.
//
// Each reader dials through guardedFetchFromEnv by default, so the suite relaxes the
// guards the way a sandbox does (SKIP_SSRF, ALLOW_INSECURE) rather than injecting a plain
// fetch: the path under test is the default one. One case leaves the guards on and shows
// the loopback origin refused. The verdicts on the bytes themselves are pinned across the
// three languages by the document-check and license-digest corpora; this suite proves the
// readers reach those checks over HTTP, and that each failure rejects with its typed error
// rather than resolving to undefined.
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { checkStrict, StrictViolation } from "../client/index.ts";
import {
	DigestMismatch,
	DirectoryResponseUnsigned,
	DirectoryUnavailable,
	MANIFEST_MEDIA_TYPE,
	ManifestVersionRefused,
	MediaTypeRefused,
	readLicenseDocument,
	readManifest,
	readRevocationList,
	readWBADirectory,
	WBA_DIRECTORY_MEDIA_TYPE,
	WBA_DIRECTORY_PATH,
} from "../resolvers/index.ts";
import { registerSeed, signedDirectoryHeaders } from "./resolvers-harness.ts";
import { hexToBytes } from "./wba-fixtures.ts";

const MANIFEST_PATH = "/.well-known/fora.json";
const LICENSE_TEXT = "Licensed for retrieval-augmented answers, attribution required.\n";
// The key of the authentication page's directory example; its seed is the RFC 8032
// test-1 seed, registered with the harness so a served directory can be signed by it.
const JWK_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const JWK = {
	kty: "OKP",
	crv: "Ed25519",
	use: "sig",
	alg: "EdDSA",
	x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	not_before: "2026-05-01T00:00:00Z",
	not_after: "2027-05-01T00:00:00Z",
};

interface Served {
	body: string;
	contentType?: string; // undefined sends no Content-Type
	status?: number;
	// Sign the response as a key directory, by every listed registered key or only by
	// those named here. The signature headers are added beside contentType.
	signedBy?: readonly string[] | "all";
	location?: string;
}

let server: Server;
let host: string;
let docs: Map<string, Served>;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(async () => {
	for (const name of ["SKIP_SSRF", "ALLOW_INSECURE"]) savedEnv[name] = process.env[name];
	process.env.SKIP_SSRF = "true";
	process.env.ALLOW_INSECURE = "true";
	docs = new Map();
	server = createServer((req, res) => {
		const doc = docs.get((req.url ?? "").split("?")[0] ?? "");
		if (doc === undefined) {
			res.writeHead(404).end();
			return;
		}
		const headers: Record<string, string> = doc.contentType === undefined ? {} : { "content-type": doc.contentType };
		if (doc.location !== undefined) headers.location = doc.location;
		const signed =
			doc.signedBy === undefined
				? Promise.resolve({})
				: signedDirectoryHeaders(req.headers.host ?? "", doc.body, doc.signedBy === "all" ? undefined : doc.signedBy);
		void signed.then((sig) => {
			const { "content-type": _ignored, ...signature } = sig as Record<string, string>;
			res.writeHead(doc.status ?? 200, { ...headers, ...signature });
			res.end(doc.body);
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	host = `127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
	for (const [name, value] of Object.entries(savedEnv)) {
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
	await new Promise<void>((resolve) => server.close(() => resolve()));
});

const plain = { scheme: "http" };

function sha256(text: string): string {
	return `sha256:${createHash("sha256").update(text).digest("hex")}`;
}

describe("readManifest", () => {
	it("returns the parsed manifest and its media type", async () => {
		docs.set(MANIFEST_PATH, {
			body: JSON.stringify({ ver: "1.0", role: "ROLE_EXCHANGE", endpoint: "https://exchange.example/rpc" }),
			contentType: "application/json; charset=utf-8",
		});
		const doc = await readManifest(host, plain);
		expect(doc.message.role).toBe("ROLE_EXCHANGE");
		expect(doc.message.endpoint).toBe("https://exchange.example/rpc");
		expect(doc.mediaType).toBe(MANIFEST_MEDIA_TYPE);
		expect(doc.url).toBe(`http://${host}${MANIFEST_PATH}`);
	});

	it.each([
		["an unknown member", { body: '{"ver":"1.0","role":"ROLE_EXCHANGE","endpoints":[]}', contentType: "application/json" }, StrictViolation],
		["a broken cross-field rule", { body: `{"ver":"1.0","role":"ROLE_EXCHANGE","terms_digest":"sha256:${"0".repeat(64)}"}`, contentType: "application/json" }, StrictViolation],
		["the wrong media type", { body: '{"ver":"1.0","role":"ROLE_EXCHANGE"}', contentType: "text/plain" }, MediaTypeRefused],
		["no media type", { body: '{"ver":"1.0","role":"ROLE_EXCHANGE"}' }, MediaTypeRefused],
		["a version read before the rest", { body: '{"ver":"2.0","role":"ROLE_EXCHANGE","endpoints":[]}', contentType: "application/json" }, ManifestVersionRefused],
		["a document that is not published", { body: "", contentType: "application/json", status: 404 }, DirectoryUnavailable],
	] as [string, Served, new (...args: never[]) => Error][])("refuses %s", async (_name, served, want) => {
		docs.set(MANIFEST_PATH, served);
		await expect(readManifest(host, plain)).rejects.toBeInstanceOf(want);
	});

	it("refuses a value that is not a bare host before dialling", async () => {
		await expect(readManifest(`${host}/elsewhere`, plain)).rejects.toThrow(/not a bare host/);
	});

	it("dials through the address guard", async () => {
		delete process.env.SKIP_SSRF;
		docs.set(MANIFEST_PATH, { body: '{"ver":"1.0","role":"ROLE_EXCHANGE"}', contentType: "application/json" });
		await expect(readManifest(host, plain)).rejects.toBeInstanceOf(DirectoryUnavailable);
	});

	it("dials through the scheme guard", async () => {
		delete process.env.ALLOW_INSECURE;
		docs.set(MANIFEST_PATH, { body: '{"ver":"1.0","role":"ROLE_EXCHANGE"}', contentType: "application/json" });
		await expect(readManifest(host, plain)).rejects.toBeInstanceOf(DirectoryUnavailable);
	});
});

describe("readWBADirectory", () => {
	beforeEach(async () => {
		await registerSeed(hexToBytes(JWK_SEED));
	});

	it("reads by domain and by URL", async () => {
		docs.set(WBA_DIRECTORY_PATH, { body: JSON.stringify({ keys: [JWK] }), contentType: WBA_DIRECTORY_MEDIA_TYPE, signedBy: "all" });
		for (const ref of [host, `http://${host}${WBA_DIRECTORY_PATH}`]) {
			const doc = await readWBADirectory(ref, plain);
			expect(doc.message.keys?.map((k) => k.x)).toEqual([JWK.x]);
			expect(doc.mediaType).toBe(WBA_DIRECTORY_MEDIA_TYPE);
		}
	});

	it.each(["application/json", "application/jwk-set+json"])("refuses a directory served as %s", async (contentType) => {
		docs.set(WBA_DIRECTORY_PATH, { body: JSON.stringify({ keys: [JWK] }), contentType, signedBy: "all" });
		await expect(readWBADirectory(host, plain)).rejects.toBeInstanceOf(MediaTypeRefused);
	});

	it("refuses a key carrying a kid", async () => {
		docs.set(WBA_DIRECTORY_PATH, {
			body: JSON.stringify({ keys: [{ ...JWK, kid: "k1" }] }),
			contentType: WBA_DIRECTORY_MEDIA_TYPE,
			signedBy: "all",
		});
		await expect(readWBADirectory(host, plain)).rejects.toBeInstanceOf(StrictViolation);
	});

	it("refuses a directory whose response no listed key signed", async () => {
		docs.set(WBA_DIRECTORY_PATH, { body: JSON.stringify({ keys: [JWK] }), contentType: WBA_DIRECTORY_MEDIA_TYPE });
		await expect(readWBADirectory(host, plain)).rejects.toBeInstanceOf(DirectoryResponseUnsigned);
	});

	it("refuses a directory listing a key that did not sign, even when another did", async () => {
		const other = { ...JWK, x: "ujxzXNvkI15srfgcQSuIOjRy0QRfrqGJ9YT4vspG40M" };
		docs.set(WBA_DIRECTORY_PATH, {
			body: JSON.stringify({ keys: [JWK, other] }),
			contentType: WBA_DIRECTORY_MEDIA_TYPE,
			signedBy: [JWK.x],
		});
		await expect(readWBADirectory(host, plain)).rejects.toBeInstanceOf(DirectoryResponseUnsigned);
	});

	it("reads a directory listing no key, which has nothing to sign", async () => {
		docs.set(WBA_DIRECTORY_PATH, { body: JSON.stringify({ keys: [] }), contentType: WBA_DIRECTORY_MEDIA_TYPE });
		expect((await readWBADirectory(host, plain)).message.keys ?? []).toEqual([]);
	});

	it("refuses a directory reached through a redirect", async () => {
		// The redirect lands on a directory that would be accepted on its own, so only a
		// reader that refuses to follow fails here.
		docs.set(WBA_DIRECTORY_PATH, { body: "", status: 302, location: "/elsewhere" });
		docs.set("/elsewhere", { body: JSON.stringify({ keys: [JWK] }), contentType: WBA_DIRECTORY_MEDIA_TYPE, signedBy: "all" });
		await expect(readWBADirectory(`http://${host}/elsewhere`, plain)).resolves.toBeDefined();
		await expect(readWBADirectory(host, plain)).rejects.toBeInstanceOf(DirectoryUnavailable);
	});
});

describe("readRevocationList", () => {
	it("returns the snapshot whatever media type it is served under", async () => {
		docs.set("/revoked", { body: '{"as_of":"2026-05-01T12:00:00Z","revoked":["tp"]}', contentType: "text/plain" });
		const doc = await readRevocationList(`http://${host}/revoked`, plain);
		expect(doc.message.revoked).toEqual(["tp"]);
		expect(doc.mediaType).toBe("text/plain");
	});

	it.each([
		["an unknown member", '{"as_of":"2026-05-01T12:00:00Z","revoked":[],"next":"x"}'],
		["a timestamp that is not RFC 3339", '{"as_of":"yesterday","revoked":[]}'],
	])("refuses %s", async (_name, body) => {
		docs.set("/revoked", { body, contentType: "application/json" });
		await expect(readRevocationList(`http://${host}/revoked`, plain)).rejects.toBeInstanceOf(StrictViolation);
	});
});

describe("readLicenseDocument", () => {
	it("verifies the digest", async () => {
		docs.set("/terms", { body: LICENSE_TEXT, contentType: "text/plain; charset=utf-8" });
		const doc = await readLicenseDocument({ uri: `http://${host}/terms`, uri_digest: sha256(LICENSE_TEXT) }, plain);
		expect(new TextDecoder().decode(doc.body)).toBe(LICENSE_TEXT);
		expect(doc.digest).toBe(sha256(LICENSE_TEXT));
		expect(doc.mediaType).toBe("text/plain");
	});

	it("refuses a digest mismatch", async () => {
		docs.set("/terms", { body: `${LICENSE_TEXT}Amended after the offer was signed.\n`, contentType: "text/plain" });
		await expect(
			readLicenseDocument({ uri: `http://${host}/terms`, uri_digest: sha256(LICENSE_TEXT) }, plain),
		).rejects.toBeInstanceOf(DigestMismatch);
	});

	it("refuses a uri without a digest before dialling", async () => {
		await expect(readLicenseDocument({ uri: `http://${host}/terms` }, plain)).rejects.toBeInstanceOf(StrictViolation);
	});

	it("reports a scheme it will not dial as unavailable", async () => {
		await expect(
			readLicenseDocument({ uri: "tdl:ai-terms/2026", uri_digest: sha256(LICENSE_TEXT) }, plain),
		).rejects.toBeInstanceOf(DirectoryUnavailable);
	});

	it("refuses a license with no uri", async () => {
		await expect(readLicenseDocument({ id: "CC-BY-4.0" }, plain)).rejects.toThrow(/no uri/);
	});
});

describe("checkStrict", () => {
	it("accepts a valid message and names a violation", () => {
		checkStrict("fora.v1.KeyRevocationList", { as_of: "2026-05-01T12:00:00Z", revoked: [] });
		try {
			checkStrict("fora.v1.KeyRevocationList", { revokedd: [] });
			expect.unreachable();
		} catch (err) {
			expect(err).toBeInstanceOf(StrictViolation);
			expect((err as StrictViolation).messageName).toBe("fora.v1.KeyRevocationList");
			expect((err as StrictViolation).violation).toContain("revokedd");
		}
	});

	it("refuses the lowerCamel spelling and reads null as absent", () => {
		expect(() => checkStrict("fora.v1.WellKnownManifest", { role: "ROLE_EXCHANGE", termsUri: "x" })).toThrow(StrictViolation);
		checkStrict("fora.v1.WellKnownManifest", { role: "ROLE_EXCHANGE", endpoint: null });
	});

	it("checks a message the SDK does not bundle against the schema it is given", async () => {
		const schema = (await import("../../../gen/jsonschema/fora.v1.Quota.schema.strict.json", { with: { type: "json" } })).default;
		expect(() => checkStrict("fora.v1.Quota", { limit: "0" }, schema)).toThrow(StrictViolation);
		expect(() => checkStrict("fora.v1.Quota", {})).toThrow(/no strict schema/);
	});
});
