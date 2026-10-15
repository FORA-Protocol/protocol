// Replay of the refusal-header corpus (refusal-header-vectors.json), over real sockets.
//
// The corpus is the cross-language contract for which failures carry the header fields of
// the answer that produced them: an answer of status 400 or above, on the RPC legs and the
// delivery fetch, and never a redirect or a 2xx the client could not read. Each row serves
// its own answer from a real server, so the fields arrive through undici exactly as they
// would in production, and the replay checks what ForaCallError.headers carries, the status
// beside it, and the discovery hint a caller parses from the two.
import { createServer, type Server } from "node:http";
import { describe, expect, it } from "vitest";

import { fetchContent } from "../client/content.ts";
import { ForaCallError } from "../client/errors.ts";
import { createUnarySend } from "../client/send.ts";
import { unaryCall } from "../client/transport.ts";
import { parseDiscoveryHint } from "../src/discovery-hint.ts";
import vectorsFile from "../../go/connect/testdata/refusal-header-vectors.json";

interface Row {
	name: string;
	leg: string;
	strict: boolean;
	status: number;
	content_type: string;
	body: string;
	headers: [string, string][];
	carried: Record<string, string>;
	hint: { content_rules: string; content_rules_state: string; exchange: string; exchange_state: string };
}

// Through unknown: the JSON module's inferred type keys each row's `carried` by that row's
// own field names, so no one Row type overlaps them all; the replay reads rows generically.
const rows = (vectorsFile as unknown as { refusals: Row[] }).refusals;

async function serving(row: Row): Promise<[Server, number]> {
	const server = createServer((_req, res) => {
		// Grouped by name, so a repeated name goes out as separate field lines.
		const lines = new Map<string, string[]>();
		for (const [name, value] of row.headers) {
			lines.set(name, [...(lines.get(name) ?? []), value]);
		}
		res.setHeader("content-type", row.content_type);
		for (const [name, values] of lines) res.setHeader(name, values);
		res.writeHead(row.status);
		res.end(row.body);
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
	return [server, (server.address() as { port: number }).port];
}

async function withLoopback<T>(run: () => Promise<T>): Promise<T> {
	const saved = [process.env["SKIP_SSRF"], process.env["ALLOW_INSECURE"]];
	process.env["SKIP_SSRF"] = "true";
	process.env["ALLOW_INSECURE"] = "true";
	try {
		return await run();
	} finally {
		if (saved[0] === undefined) delete process.env["SKIP_SSRF"];
		else process.env["SKIP_SSRF"] = saved[0];
		if (saved[1] === undefined) delete process.env["ALLOW_INSECURE"];
		else process.env["ALLOW_INSECURE"] = saved[1];
	}
}

async function failure(row: Row): Promise<ForaCallError> {
	const [server, port] = await serving(row);
	try {
		const err = await withLoopback(async () => {
			if (row.leg === "rpc") {
				return unaryCall({
					op: "discover",
					target: {
						baseURL: `http://127.0.0.1:${port}`,
						service: "fora.v1.ExchangeService",
						method: "DiscoverResources",
					},
					message: {},
					send: createUnarySend({ guarded: true }),
					strict: row.strict,
				});
			}
			const keyPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
				"sign",
				"verify",
			])) as CryptoKeyPair;
			return fetchContent(`http://127.0.0.1:${port}/doc`, { keyPair, signatureAgent: "https://agent.test" });
		}).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(ForaCallError);
		return err as ForaCallError;
	} finally {
		server.close();
	}
}

describe("refusal-header corpus", () => {
	for (const row of rows) {
		it(row.name, async () => {
			const err = await failure(row);
			if (Object.keys(row.carried).length === 0) {
				// The whole set, not only the row's names: a failure that carries nothing
				// carries nothing at all.
				expect([...err.headers]).toEqual([]);
			} else {
				expect(err.status).toBe(row.status);
				for (const [name, value] of Object.entries(row.carried)) {
					expect(err.headers.get(name)).toBe(value);
					expect(err.message).not.toContain(value);
				}
			}
			const hint = parseDiscoveryHint(err.status ?? 0, err.headers);
			expect({
				content_rules: hint.contentRules ?? "",
				content_rules_state: hint.contentRulesState,
				exchange: hint.exchange ?? "",
				exchange_state: hint.exchangeState,
			}).toEqual(row.hint);
		});
	}

	it("pins both outcomes on both legs", () => {
		const seen = new Set(rows.map((r) => `${r.leg} ${Object.keys(r.carried).length > 0}`));
		expect([...seen].sort()).toEqual(["content false", "content true", "rpc false", "rpc true"]);
		expect(rows.some((r) => r.strict)).toBe(true);
		expect(rows.some((r) => r.hint.exchange_state === "valid")).toBe(true);
	});
});
