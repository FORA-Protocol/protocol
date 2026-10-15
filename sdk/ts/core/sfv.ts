// sdk/ts RFC 8941 structured-field values: the parser and serializer the Web Bot Auth
// profile reads Signature-Input, Signature, Signature-Agent and Accept-Signature with.
// The Go oracle delegates the same job to dunglas/httpsfv; this is the dependency-free
// TS counterpart, written to the RFC 8941 §4.2 parsing algorithms and the §4.1
// serialization rules so a member parsed here re-serializes to the bytes Go produces.
//
// Only what the profile reads is modelled, which is the whole grammar except the
// top-level List: Dictionaries, Items, Inner Lists and Parameters, over Strings, Tokens,
// Integers, Decimals, Booleans and Byte Sequences. A parse never throws; it answers
// undefined for input that is not a well-formed value, so a caller refuses a header
// rather than reading half of it.

/** One RFC 8941 bare item, tagged with its type so a String and a Token that spell the
 * same characters stay distinct (Signature-Agent refuses the second). */
export type SfBareItem =
	| { type: "string"; value: string }
	| { type: "token"; value: string }
	| { type: "integer"; value: number }
	| { type: "decimal"; value: number }
	| { type: "boolean"; value: boolean }
	| { type: "bytes"; value: Uint8Array<ArrayBuffer> };

/** Parameters, in order. A repeated key keeps its first position and its last value. */
export type SfParams = Map<string, SfBareItem>;

/** An Item: a bare item and its parameters. */
export interface SfItem {
	kind: "item";
	value: SfBareItem;
	params: SfParams;
}

/** An Inner List: items and the list's own parameters. */
export interface SfInnerList {
	kind: "inner-list";
	items: SfItem[];
	params: SfParams;
}

/** A Dictionary member or a List member. */
export type SfMember = SfItem | SfInnerList;

/** A Dictionary, in member order. A repeated key keeps its first position and its last
 * value. */
export type SfDictionary = Map<string, SfMember>;

/** A cursor over one field value. */
class Input {
	pos = 0;
	constructor(readonly s: string) {}
	peek(): string {
		return this.s[this.pos] ?? "";
	}
	done(): boolean {
		return this.pos >= this.s.length;
	}
	skipSP(): void {
		while (this.s[this.pos] === " ") this.pos += 1;
	}
	skipOWS(): void {
		while (this.s[this.pos] === " " || this.s[this.pos] === "\t") this.pos += 1;
	}
}

const isDigit = (c: string): boolean => c >= "0" && c <= "9";
const isLcAlpha = (c: string): boolean => c >= "a" && c <= "z";
const isAlpha = (c: string): boolean => isLcAlpha(c) || (c >= "A" && c <= "Z");
// RFC 9110 tchar, plus the ":" and "/" RFC 8941 admits after a token's first character.
const TOKEN_CHAR = /^[!#$%&'*+\-.^_`|~0-9A-Za-z:/]$/;
const BASE64_CHAR = /^[A-Za-z0-9+/=]$/;

/** Parse a Dictionary field value (field lines already joined with ", "). */
export function parseDictionary(field: string): SfDictionary | undefined {
	const input = new Input(field);
	input.skipSP();
	const dict: SfDictionary = new Map();
	while (!input.done()) {
		const key = parseKey(input);
		if (key === undefined) return undefined;
		let member: SfMember | undefined;
		if (input.peek() === "=") {
			input.pos += 1;
			member = parseItemOrInnerList(input);
		} else {
			const params = parseParams(input);
			member = params && { kind: "item", value: { type: "boolean", value: true }, params };
		}
		if (member === undefined) return undefined;
		dict.set(key, member);
		input.skipOWS();
		if (input.done()) return dict;
		if (input.peek() !== ",") return undefined;
		input.pos += 1;
		input.skipOWS();
		if (input.done()) return undefined; // a trailing comma
	}
	return dict;
}

/** Parse an Item field value. */
export function parseItem(field: string): SfItem | undefined {
	const input = new Input(field);
	input.skipSP();
	const item = parseItemAt(input);
	if (item === undefined) return undefined;
	input.skipSP();
	return input.done() ? item : undefined;
}

function parseItemOrInnerList(input: Input): SfMember | undefined {
	return input.peek() === "(" ? parseInnerList(input) : parseItemAt(input);
}

function parseInnerList(input: Input): SfInnerList | undefined {
	input.pos += 1; // "("
	const items: SfItem[] = [];
	while (!input.done()) {
		input.skipSP();
		if (input.peek() === ")") {
			input.pos += 1;
			const params = parseParams(input);
			return params && { kind: "inner-list", items, params };
		}
		const item = parseItemAt(input);
		if (item === undefined) return undefined;
		items.push(item);
		const next = input.peek();
		if (next !== " " && next !== ")") return undefined;
	}
	return undefined; // unterminated
}

function parseItemAt(input: Input): SfItem | undefined {
	const value = parseBareItem(input);
	if (value === undefined) return undefined;
	const params = parseParams(input);
	return params && { kind: "item", value, params };
}

function parseParams(input: Input): SfParams | undefined {
	const params: SfParams = new Map();
	while (input.peek() === ";") {
		input.pos += 1;
		input.skipSP();
		const key = parseKey(input);
		if (key === undefined) return undefined;
		let value: SfBareItem | undefined = { type: "boolean", value: true };
		if (input.peek() === "=") {
			input.pos += 1;
			value = parseBareItem(input);
			if (value === undefined) return undefined;
		}
		params.set(key, value);
	}
	return params;
}

function parseKey(input: Input): string | undefined {
	const first = input.peek();
	if (!isLcAlpha(first) && first !== "*") return undefined;
	const start = input.pos;
	while (!input.done()) {
		const c = input.peek();
		if (!isLcAlpha(c) && !isDigit(c) && c !== "_" && c !== "-" && c !== "." && c !== "*") break;
		input.pos += 1;
	}
	return input.s.slice(start, input.pos);
}

function parseBareItem(input: Input): SfBareItem | undefined {
	const c = input.peek();
	if (c === "-" || isDigit(c)) return parseNumber(input);
	if (c === '"') return parseString(input);
	if (c === "*" || isAlpha(c)) return parseToken(input);
	if (c === ":") return parseBytes(input);
	if (c === "?") return parseBoolean(input);
	return undefined;
}

function parseNumber(input: Input): SfBareItem | undefined {
	let sign = 1;
	if (input.peek() === "-") {
		sign = -1;
		input.pos += 1;
	}
	if (!isDigit(input.peek())) return undefined;
	let num = "";
	let decimal = false;
	while (!input.done()) {
		const c = input.peek();
		if (isDigit(c)) {
			num += c;
		} else if (c === "." && !decimal) {
			if (num.length > 12) return undefined;
			num += c;
			decimal = true;
		} else {
			break;
		}
		input.pos += 1;
		if (!decimal && num.length > 15) return undefined;
		if (decimal && num.length > 16) return undefined;
	}
	if (!decimal) return { type: "integer", value: sign * Number(num) };
	if (num.endsWith(".") || num.length - num.indexOf(".") - 1 > 3) return undefined;
	return { type: "decimal", value: sign * Number(num) };
}

function parseString(input: Input): SfBareItem | undefined {
	input.pos += 1; // opening DQUOTE
	let out = "";
	while (!input.done()) {
		const c = input.peek();
		input.pos += 1;
		if (c === "\\") {
			const next = input.peek();
			if (next !== '"' && next !== "\\") return undefined;
			out += next;
			input.pos += 1;
		} else if (c === '"') {
			return { type: "string", value: out };
		} else {
			const code = c.charCodeAt(0);
			if (code < 0x20 || code > 0x7e) return undefined;
			out += c;
		}
	}
	return undefined; // unterminated
}

function parseToken(input: Input): SfBareItem | undefined {
	const start = input.pos;
	input.pos += 1;
	while (!input.done() && TOKEN_CHAR.test(input.peek())) input.pos += 1;
	return { type: "token", value: input.s.slice(start, input.pos) };
}

function parseBytes(input: Input): SfBareItem | undefined {
	input.pos += 1; // opening ":"
	const start = input.pos;
	while (!input.done() && input.peek() !== ":") {
		if (!BASE64_CHAR.test(input.peek())) return undefined;
		input.pos += 1;
	}
	if (input.done()) return undefined; // unterminated
	const encoded = input.s.slice(start, input.pos);
	input.pos += 1; // closing ":"
	let bin: string;
	try {
		bin = atob(encoded);
	} catch {
		return undefined;
	}
	const value = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i += 1) value[i] = bin.charCodeAt(i);
	return { type: "bytes", value };
}

function parseBoolean(input: Input): SfBareItem | undefined {
	input.pos += 1; // "?"
	const c = input.peek();
	if (c !== "0" && c !== "1") return undefined;
	input.pos += 1;
	return { type: "boolean", value: c === "1" };
}

// --- serialization (RFC 8941 §4.1) -----------------------------------------------------

/** Serialize a bare item. */
export function serializeBareItem(item: SfBareItem): string {
	switch (item.type) {
		case "string":
			return `"${item.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
		case "token":
			return item.value;
		case "integer":
			return String(item.value);
		case "decimal":
			return serializeDecimal(item.value);
		case "boolean":
			return item.value ? "?1" : "?0";
		case "bytes":
			return `:${base64(item.value)}:`;
	}
}

// A Decimal keeps at most three fractional digits and always at least one.
function serializeDecimal(value: number): string {
	const rounded = (Math.round(value * 1000) / 1000).toString();
	return rounded.includes(".") ? rounded : `${rounded}.0`;
}

function base64(bytes: Uint8Array): string {
	let bin = "";
	for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i] as number);
	return btoa(bin);
}

/** Serialize parameters: `;key` for a Boolean true, `;key=value` otherwise. */
export function serializeParams(params: SfParams): string {
	let out = "";
	for (const [key, value] of params) {
		out += value.type === "boolean" && value.value ? `;${key}` : `;${key}=${serializeBareItem(value)}`;
	}
	return out;
}

/** Serialize an Item or an Inner List, parameters included. */
export function serializeMember(member: SfMember): string {
	if (member.kind === "item") return serializeBareItem(member.value) + serializeParams(member.params);
	const items = member.items.map((it) => serializeBareItem(it.value) + serializeParams(it.params));
	return `(${items.join(" ")})${serializeParams(member.params)}`;
}

/** The string value of a parameter, or undefined when it is absent or not a String. */
export function stringParam(params: SfParams, key: string): string | undefined {
	const v = params.get(key);
	return v?.type === "string" ? v.value : undefined;
}
