// Document-read parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors the sdk/python sibling test_document_fetch_parity.py and the Go leg
// sdk/go/resolvers/document_fetch_corpus_test.go.
//
// Every document read ends in one decision about the status it was answered with, made in
// the one read every document shares: a 200 is read, a 404 is a missing document on every
// read, any 3xx is a refused redirect on a key-directory read, and anything else is an
// unavailable document. The corpus records that decision for each status; this replays it
// through fetchDocument, refusing redirects for a key directory and following them
// otherwise. Each failure is also checked for what every vector shares: it is a
// DirectoryUnavailable and never an UnknownKey, and it never carries the Location the
// server chose.
import { describe, expect, it } from "vitest";

import { DirectoryUnavailable, DocumentNotFound, RedirectRefused, UnknownKey } from "../resolvers/errors.ts";
import { type FetchLike, fetchDocument } from "../resolvers/fetch.ts";
import vectorsFile from "../../go/resolvers/testdata/document-fetch-vectors.json";

type DocumentFetchVector = {
	name: string;
	read: string;
	status: number;
	location: string;
	verdict: string;
};
const vectors = (vectorsFile as { vectors: DocumentFetchVector[] }).vectors;

const URL_READ = "https://publisher.example/.well-known/http-message-signatures-directory";

// answering serves the vector's answer to every request: its status, and its Location
// when it carries one. A 3xx and a 304 carry no body.
function answering(v: DocumentFetchVector): FetchLike {
	return async () => new Response(null, { status: v.status, headers: v.location !== "" ? { location: v.location } : {} });
}

async function read(v: DocumentFetchVector): Promise<unknown> {
	expect(["key_directory", "document"]).toContain(v.read);
	try {
		await fetchDocument(answering(v), URL_READ, { noRedirect: v.read === "key_directory" });
		return undefined;
	} catch (err) {
		return err;
	}
}

describe("document-fetch corpus", () => {
	it("carries a control for each read", () => {
		const reads = new Set(vectors.filter((v) => v.verdict === "ok").map((v) => v.read));
		expect([...reads].sort()).toEqual(["document", "key_directory"]);
	});

	it.each(vectors.map((v) => [v.name, v] as const))("%s", async (_name, v) => {
		const failure = await read(v);
		if (v.verdict === "ok") {
			expect(failure).toBeUndefined();
			return;
		}
		expect(failure).toBeInstanceOf(DirectoryUnavailable);
		expect(failure).not.toBeInstanceOf(UnknownKey);
		// Specific before generic: both subclasses are DirectoryUnavailable too.
		const got =
			failure instanceof RedirectRefused
				? "redirect_refused"
				: failure instanceof DocumentNotFound
					? "not_found"
					: "unavailable";
		expect(got).toBe(v.verdict);
		if (v.location !== "") expect((failure as Error).message).not.toContain(v.location);
	});
});
