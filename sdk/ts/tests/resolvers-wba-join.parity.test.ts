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
// vector is {label, domain, port, expected_host, dialable}.
//
// Asserted through createWBAOfferDirectoryFetch with an injected FetchLike that
// records the URL it is handed, never through the join helper itself, which stays
// module-private so it cannot become a TypeScript-only public symbol. Two things
// are proved that way instead of one: the join agrees with Go, AND the fetch really
// builds its URL from the shared wbaDirectoryURL builder rather than from a string
// of its own.
//
// Three of the oracle's answers do not form a URL at all, and for those the
// contract is that NOTHING is dialled and the failure is contained as undefined.
// Two things make that assertable here. The injected fetch parses the URL with
// `new URL()` and throws a TypeError before recording, which is what globalThis
// fetch does with an unformable URL — a recorder that only appended the string
// could never reach the refusal it is supposed to prove. And which vectors those
// are comes from the corpus's `dialable` field rather than from a check written in
// this file, so all three replays branch on one value. Before that, this suite
// asserted the malformed string IS dialled while the Python suite asserted it is
// not, and the corpus written to end a three-way split held two answers.
import { describe, expect, it } from "vitest";

import corpus from "../../go/resolvers/testdata/wba-join-vectors.json";
import { createWBAOfferDirectoryFetch, wbaDirectoryURL } from "../resolvers/index.ts";

interface WbaJoinVector {
	label: string;
	domain: string;
	port: string;
	expected_host: string;
	dialable: boolean;
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
// Each vector also carries `dialable`: whether that joined authority forms a URL a
// transport accepts. Three of the six do not, and the contract for those is that the
// fetch dials nothing and returns undefined.
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
				// Parse before recording, the way globalThis fetch does: an authority
				// no URL parser accepts never becomes a request, and the TypeError is
				// what the fetcher's catch arm contains as undefined.
				new URL(url);
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
			const result = await fetch(vec.domain);

			if (!vec.dialable) {
				expect(
					dialled,
					`${vec.label}: the Go oracle joins domain=${vec.domain} port=${vec.port} to ` +
						`${vec.expected_host}, which is not a valid authority — the fetch must dial nothing`,
				).toEqual([]);
				expect(
					result,
					`${vec.label}: an unformable URL must be contained as undefined`,
				).toBeUndefined();
				return;
			}

			expect(dialled).toEqual([wbaDirectoryURL("https", vec.expected_host)]);
		});
	}
});
