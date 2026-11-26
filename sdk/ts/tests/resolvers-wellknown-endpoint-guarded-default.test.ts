// What the shared corpus does not carry about the endpoint resolver's DEFAULT transport.
// Which outcome the default gives for a loopback, private or link-local address and for
// plain http is pinned across the three languages by resolver-default-vectors.json
// (resolver-defaults.parity.test.ts). The cases here are the ones that corpus does not
// express: a host NAME that resolves to a reserved address, IPv4 and IPv6, rather than an
// IP literal; an injected transport used exactly as given; and the guarded transport built
// once per resolver rather than per resolve. Python pins the same three cases in
// test_resolvers_wellknown_endpoint_guarded_default.py.
//
// Nothing in the SDK is mocked. The test replaces `lookup` from node:dns/promises, the
// resolver the guard's connector calls, so a few .example names answer with reserved
// addresses and no listener is needed on them; the fake records every name it is asked,
// so a test can show the refusal came from the fake's answer and not from a name that does
// not resolve. It also wraps undici's Agent to count the dispatchers built. Both are
// libraries the SDK depends on, not the SDK.
import { beforeEach, describe, expect, it, vi } from "vitest";

const { dnsAnswers, dnsAsked, agents } = vi.hoisted(() => ({
	dnsAnswers: new Map<string, string>(),
	dnsAsked: [] as string[],
	agents: { built: 0 },
}));

vi.mock("node:dns/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:dns/promises")>();
	const lookup = (async (host: string, opts?: unknown) => {
		dnsAsked.push(host);
		const address = dnsAnswers.get(host);
		if (address === undefined) return actual.lookup(host, opts as never);
		return [{ address, family: address.includes(":") ? 6 : 4 }];
	}) as typeof actual.lookup;
	return { ...actual, lookup, default: { ...actual, lookup } };
});

vi.mock("undici", async (importOriginal) => {
	const actual = await importOriginal<typeof import("undici")>();
	class CountingAgent extends actual.Agent {
		constructor(...args: ConstructorParameters<typeof actual.Agent>) {
			super(...args);
			agents.built += 1;
		}
	}
	return { ...actual, Agent: CountingAgent };
});

import { createWellKnownEndpointResolver, DirectoryUnavailable, SsrfBlockedError } from "../resolvers/index.ts";
import { loopbackFetch, manifestJson, startOrigin } from "./harness/origin.ts";
import { isolateSsrfEnv } from "./harness/ssrf-env.ts";

isolateSsrfEnv();

beforeEach(() => {
	dnsAnswers.clear();
	dnsAsked.length = 0;
});

/** The rejection a resolve ends in, asserted to be a guard refusal: a DirectoryUnavailable
 * (a failed read, the only retryable exit) caused by the guarded transport's
 * SsrfBlockedError, so a refusal for any other reason does not pass. */
async function expectGuardRefusal(resolve: Promise<unknown>): Promise<SsrfBlockedError> {
	const err = await resolve.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(DirectoryUnavailable);
	const cause = (err as { cause?: unknown }).cause;
	expect(cause).toBeInstanceOf(SsrfBlockedError);
	return cause as SsrfBlockedError;
}

describe("createWellKnownEndpointResolver default transport", () => {
	for (const [name, address] of [
		["private IPv4 (10/8)", "10.0.0.5"],
		["private IPv4 (192.168/16)", "192.168.1.10"],
		["link-local IPv4 (cloud metadata)", "169.254.169.254"],
		["unique-local IPv6", "fd00::1"],
		["link-local IPv6", "fe80::1"],
	] as const) {
		it(`refuses an Exchange whose name resolves to a ${name} address`, async () => {
			// The default https scheme with no flag set, so only the address guard can refuse.
			dnsAnswers.set("exchange.example", address);
			const r = createWellKnownEndpointResolver();
			const refusal = await expectGuardRefusal(r.resolveEndpoint("exchange.example"));
			// The generic refusal: it names the host, never the address it resolved to.
			expect(refusal.message).toBe("SSRF guard: refusing to dial exchange.example");
			// The guard asked the fake, so the refusal is of its reserved answer; a name that
			// did not resolve at all would be refused with the same message.
			expect(dnsAsked).toContain("exchange.example");
		});
	}

	it("uses an injected transport exactly as given, with no guard of its own", async () => {
		// No flags are set, so the guarded default would refuse this loopback origin: only
		// the injected transport, used as given, can reach it.
		const origin = await startOrigin();
		origin.setManifest(manifestJson(`http://${origin.host}/fora.v1.ExchangeService`));
		const asked: string[] = [];
		try {
			const r = createWellKnownEndpointResolver({
				scheme: "http",
				fetch: (url) => {
					asked.push(url);
					return loopbackFetch(url);
				},
			});
			expect(await r.resolveEndpoint(origin.host)).toBe(`http://${origin.host}/fora.v1.ExchangeService`);
			expect(asked).toEqual([`http://${origin.host}/.well-known/fora.json`]);
		} finally {
			await origin.close();
		}
	});

	it("builds its guarded transport once per resolver, not once per resolve", async () => {
		// guardedFetchFromEnv() constructs an undici Agent, so a default built per resolve
		// would leave one dispatcher behind per call. A refusal is never cached, so each of
		// the three resolves below goes back to the transport.
		const before = agents.built;
		const r = createWellKnownEndpointResolver();
		expect(agents.built - before).toBe(1);
		for (let i = 0; i < 3; i++) await expectGuardRefusal(r.resolveEndpoint("127.0.0.1:9"));
		expect(agents.built - before).toBe(1);
	});
});
