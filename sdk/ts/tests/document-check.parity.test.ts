// Replay the document-check and license-digest corpora through the TypeScript readers'
// checks (TypeScript side).
//
// Both corpora are emitted by the Go oracle (sdk/go/resolvers/gen_document_check_vectors_test.go)
// by running the pure decision each document reader ends in. Replaying them here holds
// accept and verifyDigest to the same verdict for the same bytes and Content-Type, so a
// harness reading a party's documents through any of the three SDKs reports the same
// finding.
import { describe, expect, it } from "vitest";

import documents from "../../go/resolvers/testdata/document-check-vectors.json";
import digests from "../../go/resolvers/testdata/license-digest-vectors.json";
import {
	accept,
	type DocumentKind,
	MANIFEST,
	REVOCATION_LIST,
	verifyDigest,
	WBA_DIRECTORY,
} from "../resolvers/documents.ts";
import {
	DigestMismatch,
	DirectoryUnavailable,
	ManifestVersionRefused,
	MediaTypeRefused,
} from "../resolvers/errors.ts";
import { mediaTypeEssence } from "../resolvers/http.ts";
import { StrictViolation } from "../src/strict.ts";

interface DocumentVector {
	label: string;
	document: string;
	content_type: string;
	body: string;
	verdict: string;
}
interface DigestVector {
	label: string;
	body: string;
	uri_digest: string;
	verdict: string;
	digest: string;
}

const KINDS: Record<string, DocumentKind<unknown>> = {
	manifest: MANIFEST,
	wba_directory: WBA_DIRECTORY,
	revocation_list: REVOCATION_LIST,
};

function verdictOf(v: DocumentVector): string {
	const fetched = {
		url: "https://party.example/doc",
		body: new TextEncoder().encode(v.body),
		// "" means the header was absent.
		mediaType: mediaTypeEssence(v.content_type === "" ? null : v.content_type),
	};
	try {
		accept(KINDS[v.document] as DocumentKind<unknown>, fetched);
		return "ok";
	} catch (err) {
		if (err instanceof MediaTypeRefused) return "media_type";
		if (err instanceof DirectoryUnavailable) return "undecodable";
		if (err instanceof ManifestVersionRefused) return "version";
		if (err instanceof StrictViolation) return "strict";
		throw err;
	}
}

const documentVectors = (documents as { vectors: DocumentVector[] }).vectors;
const digestVectors = (digests as { vectors: DigestVector[] }).vectors;

describe("document-check corpus", () => {
	it("is not empty", () => {
		expect(documentVectors.length).toBeGreaterThan(0);
		expect(digestVectors.length).toBeGreaterThan(0);
	});

	for (const v of documentVectors) {
		it(v.label, () => {
			expect(verdictOf(v)).toBe(v.verdict);
		});
	}
});

describe("license-digest corpus", () => {
	it("refuses a digest of the right length that differs only in its last character", async () => {
		const ok = digestVectors.find((x) => x.verdict === "ok") as (typeof digestVectors)[number];
		const last = ok.uri_digest.slice(-1);
		const altered = ok.uri_digest.slice(0, -1) + (last === "0" ? "1" : "0");
		const fetched = { url: "https://publisher.example/terms", body: new TextEncoder().encode(ok.body), mediaType: undefined };
		await expect(verifyDigest(altered, fetched)).rejects.toThrow(DigestMismatch);
	});

	for (const v of digestVectors) {
		it(v.label, async () => {
			const fetched = {
				url: "https://publisher.example/terms",
				body: new TextEncoder().encode(v.body),
				mediaType: undefined,
			};
			if (v.verdict === "mismatch") {
				await expect(verifyDigest(v.uri_digest, fetched)).rejects.toThrow(DigestMismatch);
				return;
			}
			expect(v.verdict).toBe("ok");
			expect((await verifyDigest(v.uri_digest, fetched)).digest).toBe(v.digest);
		});
	}
});
