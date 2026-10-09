// `WBAKeyResolver.revoked` finds the list it answers from by directory identity. A
// snapshot is stored under the host a fetch spelled, and a caller may name the same
// directory another way — an offer's bare exchange domain, an origin with :443 written
// out, different letter case. Those name the same party under the request-recipient
// identity rule, so they must reach the same list: matching the spelling only would
// read a revoked key as unrevoked. A subdomain is a different party and never borrows
// the list. Port of the Go TestRevokedMatchesTheDirectoryIdentity.
//
// The directory is served for exchange.example by routing that origin to a loopback
// listener; it lists no key, so it carries no response signature to bind to a host.
import { afterEach, describe, expect, it } from "vitest";
import { createWBAKeyResolver, type FetchLike } from "../resolvers/index.ts";
import { type Origin, revocationJson, startOrigin, wbaFileJson } from "./resolvers-harness.ts";

const AS_OF = "2026-05-01T12:00:00Z";

describe("WBAKeyResolver.revoked matches the directory identity", () => {
	let origin: Origin | undefined;
	afterEach(async () => {
		await origin?.close();
		origin = undefined;
	});

	it("reaches one directory's list by any spelling of its identity, and only that list", async () => {
		origin = await startOrigin();
		const loopback = origin.url;
		const revocationPath = new URL(origin.revocationURL()).pathname;
		origin.setWBA(wbaFileJson([], `https://exchange.example${revocationPath}`));
		origin.setRevocation(revocationJson(AS_OF, ["tp"]));
		const route: FetchLike = (url, init) =>
			fetch(url.replace(/^https:\/\/exchange\.example/, loopback), init?.redirect === "manual" ? { redirect: "manual" } : {});

		const r = createWBAKeyResolver({ fetch: route, now: () => Date.parse(AS_OF) });
		// A keyless directory resolves nothing, yet its list loads.
		expect(await r.resolve("unknown", "https://exchange.example")).toBeUndefined();

		const cases: [string, string, boolean][] = [
			["tp", "https://exchange.example", true],
			["tp", "exchange.example", true],
			["tp", "https://Exchange.EXAMPLE", true],
			["tp", "https://exchange.example:443", true],
			["tp", "exchange.example:443", true],
			["tp", "https://sub.exchange.example", false],
			["tp", "https://example", false],
			["tp", "https://exchange.example:8443", false],
			["other", "https://exchange.example", false],
			["tp", "", false],
			["", "https://exchange.example", false],
		];
		for (const [keyId, directory, want] of cases) {
			expect(r.revoked(keyId, directory), `${keyId} @ ${directory}`).toBe(want);
		}
	});
});
