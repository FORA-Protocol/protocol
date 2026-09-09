// A Zod node this inversion cannot read must be an error, not a kind nothing matches:
// a silent "Zod" kind would drop presence-tracked zero values from the canonical form
// and fail offer signature verification with no cause.
import { describe, expect, it } from "vitest";

import { kindOf } from "../core/wire-canon.ts";

describe("kindOf", () => {
	it("reads Zod 3 typeName and Zod 4 string type", () => {
		expect(kindOf({ _def: { typeName: "ZodOptional" } })).toBe("ZodOptional");
		expect(kindOf({ _def: { type: "optional" } })).toBe("ZodOptional");
	});
	it("throws on a node with neither", () => {
		expect(() => kindOf({ _def: {} })).toThrow("neither typeName");
	});
});
