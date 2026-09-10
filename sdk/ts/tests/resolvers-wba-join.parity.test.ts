// Cross-language fetcher-level host+port join parity (TypeScript side).
//
// The pure URL builder is already pinned by wba-url-vectors.json, but that corpus
// takes an ALREADY-JOINED host. The join that produces the host lives in each
// language's directory fetcher, and it was hand-written three times: Go used
// net.JoinHostPort, TypeScript interpolated without bracketing, and Python
// bracketed only an unbracketed literal. The three disagreed on an IPv6 host, so
// one exchange domain resolved to different URLs depending on the SDK.
//
// sdk/go/resolvers/testdata/wba-join-vectors.json is what ends that. It is emitted
// by RUNNING the Go joinDirectoryHost oracle, and this suite replays it. Each
// vector is {label, domain, port, expected_host}.
//
// Asserted through createWBAOfferDirectoryFetch with an injected FetchLike that
// records the URL it is handed, never through the join helper itself, which stays
// module-private so it cannot become a TypeScript-only public symbol. Two things
// are proved that way instead of one: the join agrees with Go, AND the fetch really
// builds its URL from the shared wbaDirectoryURL builder rather than from a string
// of its own.
import { describe, expect, it } from "vitest";

import corpus from "../../go/resolvers/testdata/wba-join-vectors.json";
import { createWBAOfferDirectoryFetch, wbaDirectoryURL } from "../resolvers/index.ts";

interface WbaJoinVector {
	label: string;
	domain: string;
	port: string;
	expected_host: string;
}
interface WbaJoinCorpus {
	note: string;
	vectors: WbaJoinVector[];
}

const c = corpus as WbaJoinCorpus;

// The corpus MUST cover exactly these behaviors (stated here as the contract so a
// thinner corpus fails this suite, not just the completeness gate):
//   - empty-port           : the domain passes through so the scheme default applies
//   - plain-domain         : an ordinary domain gains :port
//   - bare-ipv6            : an unbracketed IPv6 literal gains brackets before the port
//   - bracketed-ipv6       : an already-bracketed literal is bracketed AGAIN, as
//                            net.JoinHostPort does
//   - domain-with-port     : a domain already carrying a port is treated as a
//                            colon-bearing host and bracketed
//   - empty-port-bare-ipv6 : an empty port wins over the colon rule
const REQUIRED_LABELS = [
	"empty-port",
	"plain-domain",
	"bare-ipv6",
	"bracketed-ipv6",
	"domain-with-port",
	"empty-port-bare-ipv6",
];

describe("WBA fetcher host+port join parity with the Go oracle", () => {
	it("the corpus is non-empty", () => {
		expect(c.vectors.length).toBeGreaterThan(0);
	});

	it("the corpus covers every required behavior", () => {
		const labels = new Set(c.vectors.map((v) => v.label));
		const missing = REQUIRED_LABELS.filter((l) => !labels.has(l));
		expect(missing).toEqual([]);
	});

	for (const vec of c.vectors) {
		it(`dials the host the Go oracle joins: ${vec.label}`, async () => {
			const dialled: string[] = [];
			const recordingFetch = async (url: string) => {
				dialled.push(url);
				// An empty body is enough: the fetch's decode arm turns it into
				// undefined, and this suite asserts on the URL rather than on the
				// decoded directory.
				return { status: 200, text: async () => "" };
			};

			const fetch = createWBAOfferDirectoryFetch({
				fetch: recordingFetch,
				scheme: "https",
				port: vec.port,
			});
			await fetch(vec.domain);

			expect(dialled).toEqual([wbaDirectoryURL("https", vec.expected_host)]);
		});
	}
});
