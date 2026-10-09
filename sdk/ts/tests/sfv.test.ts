// Unit tests for the RFC 8941 structured-field parser and serializer (core/sfv.ts), a
// parser and so a permitted unit-test target. The profile suites reach it through
// Signature-Input, Signature and Signature-Agent; these pin the grammar edges the
// Go-emitted vectors are too well-behaved to reach.

import { describe, expect, it } from "vitest";
import { parseDictionary, parseItem, serializeMember } from "../core/sfv.ts";

describe("RFC 8941 dictionary parsing", () => {
	it("parses members, inner lists, parameters and every bare-item type", () => {
		const dict = parseDictionary('a=1, b=-2.5, c="s\\"q", d=tok/en:x, e=:AQID:, f=?0, g, h=(1 "x";p);q=*t');
		expect(dict).toBeDefined();
		const get = (k: string) => dict?.get(k);
		expect(get("a")).toMatchObject({ kind: "item", value: { type: "integer", value: 1 } });
		expect(get("b")).toMatchObject({ kind: "item", value: { type: "decimal", value: -2.5 } });
		expect(get("c")).toMatchObject({ kind: "item", value: { type: "string", value: 's"q' } });
		expect(get("d")).toMatchObject({ kind: "item", value: { type: "token", value: "tok/en:x" } });
		expect(get("e")).toMatchObject({ kind: "item", value: { type: "bytes", value: Uint8Array.from([1, 2, 3]) } });
		expect(get("f")).toMatchObject({ kind: "item", value: { type: "boolean", value: false } });
		expect(get("g")).toMatchObject({ kind: "item", value: { type: "boolean", value: true } });
		expect(get("h")?.kind).toBe("inner-list");
	});

	it("keeps the first position and the last value of a repeated key", () => {
		const dict = parseDictionary('a=1, b=2, a=3');
		expect([...(dict?.keys() ?? [])]).toEqual(["a", "b"]);
		expect(dict?.get("a")).toMatchObject({ value: { value: 3 } });
	});

	it("tolerates optional whitespace around commas and leading spaces", () => {
		expect(parseDictionary('  a=1 ,\tb=2')?.size).toBe(2);
	});

	it("refuses what is not a dictionary", () => {
		for (const bad of [
			"a=1,", // trailing comma
			"A=1", // uppercase key
			'a="unterminated',
			'a="bad \\x escape"',
			"a=(1 2", // unterminated inner list
			"a=(1 2)x",
			"a=:not base64!:",
			"a=?2",
			"a=1234567890123456", // integer longer than 15 digits
			"a=1.2345", // decimal with more than three fractional digits
			"a=1.",
			"a=1 b=2", // missing comma
			'"https://agent.example"',
			"https://agent.example",
		]) {
			expect(parseDictionary(bad), bad).toBeUndefined();
		}
	});

	it("parses an empty field as an empty dictionary", () => {
		expect(parseDictionary("")?.size).toBe(0);
	});
});

describe("RFC 8941 item parsing", () => {
	it("tells a String from the Token that spells the same characters", () => {
		expect(parseItem('"https://agent.example"')?.value).toEqual({ type: "string", value: "https://agent.example" });
		expect(parseItem("https://agent.example")?.value).toEqual({ type: "token", value: "https://agent.example" });
	});

	it("refuses trailing content", () => {
		expect(parseItem('"a" "b"')).toBeUndefined();
		expect(parseItem('"a", "b"')).toBeUndefined();
	});
});

describe("RFC 8941 serialization", () => {
	it("re-serializes a parsed member canonically, whatever its spacing", () => {
		const dict = parseDictionary('sig1=(  "@method"   "signature-agent";key="sig1"  );created=1;keyid="k";req, b="x";type=directory');
		const sig1 = dict?.get("sig1");
		const b = dict?.get("b");
		if (sig1 === undefined || b === undefined) throw new Error("parse failed");
		expect(serializeMember(sig1)).toBe('("@method" "signature-agent";key="sig1");created=1;keyid="k";req');
		expect(serializeMember(b)).toBe('"x";type=directory');
	});

	it("escapes quotes and backslashes in a String and pads a Byte Sequence", () => {
		const dict = parseDictionary('a="q\\"\\\\", b=:AQ==:, c=-1.5');
		expect(serializeMember(dict?.get("a") ?? fail())).toBe('"q\\"\\\\"');
		expect(serializeMember(dict?.get("b") ?? fail())).toBe(":AQ==:");
		expect(serializeMember(dict?.get("c") ?? fail())).toBe("-1.5");
	});
});

function fail(): never {
	throw new Error("member missing");
}
