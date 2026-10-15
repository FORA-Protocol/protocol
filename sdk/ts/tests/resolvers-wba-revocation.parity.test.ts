// Cross-language revocation-set-membership parity (TypeScript side).
//
// sdk/ts `revoked(keyId, directory)` MUST reproduce the sdk/go oracle's verdict for
// every case in sdk/go/resolvers/testdata/revocation-membership-vectors.json. The
// vector carries two served WBA directories, each with its keys, its own revocation
// snapshot (as_of + revoked thumbprints) and a prime thumbprint resolved to load that
// snapshot, and labelled (thumbprint, directory) cases with the expected verdict.
// This test serves each directory on its own REAL origin (the shared harness),
// resolves every prime thumbprint in the order the vector lists them, then asserts
// `revoked(tp, directory)` matches the oracle for EVERY case. Directory B lists no
// key and its list names directory A's key, so the corpus pins the load-bearing rule:
// a list answers only for its own directory, and A's key still resolves against A
// after B's list has loaded.
//
// A directory is served signed by every key it lists, as the profile requires: the Go
// emitter derives A's key from the fixed seed "present.v1" (zero-padded to 32 bytes),
// so the harness registers the same seed. B lists no key, so it has nothing to sign.
import { afterEach, describe, expect, it } from "vitest";
import vector from "../../go/resolvers/testdata/revocation-membership-vectors.json";
import { createWBAKeyResolver } from "../resolvers/index.ts";
import {
	type Origin,
	registerSeed,
	revocationJson,
	startOrigin,
	wbaFileJson,
	wbaJwk,
	httpsToLoopback,
} from "./resolvers-harness.ts";

interface RevMembershipDirectory {
	directory: string;
	directory_keys: { x: string; not_before: string; not_after: string }[];
	revoked: string[];
	prime_thumbprint: string;
	prime_resolves: boolean;
}
interface RevMembershipCase {
	label: string;
	thumbprint: string;
	directory: string;
	form: "origin" | "bare";
	expected_revoked: boolean;
}
interface RevMembershipVector {
	as_of: string;
	directories: RevMembershipDirectory[];
	cases: RevMembershipCase[];
}

const vec = vector as RevMembershipVector;

describe("sdk/ts revoked() matches the sdk/go revocation-membership oracle", () => {
	const origins = new Map<string, Origin>();
	afterEach(async () => {
		for (const o of origins.values()) await o.close();
		origins.clear();
	});

	it("has a non-empty case corpus over two directories", () => {
		expect(vec.cases.length).toBeGreaterThan(0);
		expect(new Set(vec.directories.map((d) => d.directory))).toEqual(new Set(["A", "B"]));
	});

	it("reproduces the oracle verdict for every labelled case", async () => {
		const seed = new Uint8Array(32);
		seed.set(new TextEncoder().encode("present.v1"));
		const present = await registerSeed(seed);
		expect(vec.directories.flatMap((d) => d.directory_keys.map((k) => k.x))).toEqual([present.x]);

		for (const d of vec.directories) {
			const origin = await startOrigin();
			origins.set(d.directory, origin);
			const keys = d.directory_keys.map((k) => wbaJwk(k.x, k.not_before, k.not_after));
			origin.setWBA(wbaFileJson(keys, origin.revocationURL()));
			origin.setRevocation(revocationJson(vec.as_of, d.revoked));
		}

		const r = createWBAKeyResolver({
			fetch: httpsToLoopback,
			now: () => Date.parse(vec.as_of),
		});
		// Load every directory's list, in the vector's order, by resolving its prime
		// thumbprint. A keyless directory resolves nothing, yet its list still loads.
		for (const d of vec.directories) {
			const origin = origins.get(d.directory) as Origin;
			const key = await r.resolve(d.prime_thumbprint, origin.url);
			expect(key !== undefined, `prime ${d.directory}`).toBe(d.prime_resolves);
		}

		const reference = (c: RevMembershipCase): string => {
			if (c.directory === "") return "";
			const origin = origins.get(c.directory) as Origin;
			return c.form === "bare" ? origin.host : `https://${origin.host}`;
		};
		for (const c of vec.cases) {
			expect(r.revoked(c.thumbprint, reference(c)), c.label).toBe(c.expected_revoked);
		}
		// Empty keyId is never revoked (parity with the Go accessor guard).
		expect(r.revoked("", `https://${(origins.get("A") as Origin).host}`)).toBe(false);
	});
});
