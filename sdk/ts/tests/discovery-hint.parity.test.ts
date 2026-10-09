// Replay of the shared discovery-hint corpus against the Go oracle.
//
// Each `parse` row is fed to parseDiscoveryHint through a fetch `Headers` built
// from the row's ordered [name, value] pairs, which is what an agent holds after
// a real fetch. Each `reconcile` row parses the same way and then checks the
// hinted Exchange against the domains the publisher manifest lists. Pinned to
// discovery-hint-vectors.json.

import { describe, expect, it } from "vitest";
import vectorsFile from "../../go/helpers/testdata/discovery-hint-vectors.json";
import {
	type DiscoveryHint,
	parseDiscoveryHint,
	reconcileDiscoveryHint,
} from "../src/discovery-hint.ts";
import { ContentRulesHeader, ExchangeHeader } from "../src/wire.ts";

type Expected = {
	content_rules: string;
	content_rules_state: string;
	exchange: string;
	exchange_state: string;
};
type ParseVector = { name: string; status: number; headers: [string, string][]; expected: Expected };
type ReconcileVector = {
	name: string;
	status: number;
	headers: [string, string][];
	listed: string[];
	expected_agreement: string;
};
type DiscoveryHintFile = {
	header_names: { content_rules: string; exchange: string };
	parse: ParseVector[];
	reconcile: ReconcileVector[];
};

const doc = vectorsFile as DiscoveryHintFile;

// A received header value is a byte string, so a non-ASCII row reaches Headers
// as its UTF-8 bytes read one per character, the way undici hands a raw header to
// Headers. Decoding back gives the string the Go oracle saw.
const toByteString = (v: string): string => String.fromCharCode(...new TextEncoder().encode(v));
const fromByteString = (v: string): string =>
	new TextDecoder().decode(Uint8Array.from(v, (c) => c.charCodeAt(0)));

function headersOf(pairs: [string, string][]): Headers {
	const h = new Headers();
	for (const [name, value] of pairs) {
		h.append(name, toByteString(value));
	}
	return h;
}

/** The hint in the corpus's vocabulary, where an unset value is "". */
function asExpected(hint: DiscoveryHint): Expected {
	return {
		content_rules: hint.contentRules === undefined ? "" : fromByteString(hint.contentRules),
		content_rules_state: hint.contentRulesState,
		exchange: hint.exchange === undefined ? "" : fromByteString(hint.exchange),
		exchange_state: hint.exchangeState,
	};
}

describe("discovery-hint corpus", () => {
	it("names the headers the constants name", () => {
		expect(doc.header_names).toEqual({ content_rules: ContentRulesHeader, exchange: ExchangeHeader });
	});

	it("exercises every state and every agreement", () => {
		const states = new Set(doc.parse.flatMap((v) => [v.expected.content_rules_state, v.expected.exchange_state]));
		expect([...states].sort()).toEqual(["absent", "malformed", "valid"]);
		const agreements = new Set(doc.reconcile.map((v) => v.expected_agreement));
		expect([...agreements].sort()).toEqual(["listed", "no_exchange", "unlisted"]);
	});

	for (const v of doc.parse) {
		it(`parse: ${v.name}`, () => {
			expect(asExpected(parseDiscoveryHint(v.status, headersOf(v.headers)))).toEqual(v.expected);
		});
	}

	for (const v of doc.reconcile) {
		it(`reconcile: ${v.name} → ${v.expected_agreement}`, () => {
			const hint = parseDiscoveryHint(v.status, headersOf(v.headers));
			expect(reconcileDiscoveryHint(hint, v.listed)).toBe(v.expected_agreement);
		});
	}

	it("reads the headers of a real 403 Response", () => {
		const resp = new Response(null, {
			status: 403,
			headers: {
				"X-Content-Rules": "https://publisher.example/.well-known/fora.json",
				"X-FORA-Exchange": "exchange.example",
			},
		});
		const hint = parseDiscoveryHint(resp.status, resp.headers);
		expect(hint).toEqual({
			contentRules: "https://publisher.example/.well-known/fora.json",
			contentRulesState: "valid",
			exchange: "exchange.example",
			exchangeState: "valid",
		});
		expect(reconcileDiscoveryHint(hint, ["exchange.example"])).toBe("listed");
		expect(reconcileDiscoveryHint(hint, ["other-exchange.example"])).toBe("unlisted");
	});

	it("trims a hand-written reader's value the way Headers does", () => {
		const reader = { get: (n: string) => (n.toLowerCase() === "x-fora-exchange" ? " exchange.example\t" : null) };
		const hint = parseDiscoveryHint(403, reader);
		expect(hint.exchange).toBe("exchange.example");
		expect(hint.contentRulesState).toBe("absent");
	});
});
