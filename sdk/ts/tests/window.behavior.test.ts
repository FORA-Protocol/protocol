// Window behaviour (TypeScript side): clockWindow floors created and adds ttl;
// the deprecated monotonicWindow signs at the clock's time exactly as clockWindow.
//
// The signature Window (Go core/sigwindow.go) carries a clock → NOT vector-
// gated. Two faces:
//   - clockWindow(now, ttlSec): created = floor(now()), expires = created+ttl
//     (MUST floor — Go .Unix() floors; current signInbound uses
//      Math.floor(now()); an un-floored default would change signature bytes).
//   - monotonicWindow(now, ttlSec): deprecated, identical to clockWindow (Go
//     core.MonotonicWindow). It no longer moves created into the future during a
//     burst; the per-signature nonce is what makes each signature unique.
import { describe, it, expect } from "vitest";
import { clockWindow, monotonicWindow } from "../core/window.ts";

describe("sdk/ts clockWindow floors created and adds ttl to expires", () => {
	it("created = floor(now), expires = floor(now)+ttl for a fractional now", () => {
		// A fractional-second now (seconds domain, matching Go's now().Unix()).
		const now = () => 1_700_000_000.987;
		const w = clockWindow(now, 600);
		const [created, expires] = w();
		expect(created).toBe(1_700_000_000); // floored, not 1700000000.987
		expect(expires).toBe(1_700_000_600); // created + 600, integer
		expect(Number.isInteger(created)).toBe(true);
		expect(Number.isInteger(expires)).toBe(true);
	});

	it("reads the clock on every invocation", () => {
		let t = 1_000.0;
		const w = clockWindow(() => t, 60);
		expect(w()).toEqual([1_000, 1_060]);
		t = 2_000.5;
		expect(w()).toEqual([2_000, 2_060]);
	});
});

describe("sdk/ts monotonicWindow signs at the clock's current time", () => {
	it("returns (now, now+ttl) for every call of a 1000-call burst in one frozen second", () => {
		const w = monotonicWindow(() => 1_700_000_000.4, 300);
		for (let i = 0; i < 1000; i += 1) {
			expect(w()).toEqual([1_700_000_000, 1_700_000_300]);
		}
	});

	it("never stamps created ahead of the clock, and follows the clock as it moves", () => {
		let t = 1_700_000_000;
		const w = monotonicWindow(() => t, 60);
		for (let i = 0; i < 5; i += 1) w();
		t = 1_700_000_001;
		expect(w()).toEqual([1_700_000_001, 1_700_000_061]);
		t = 1_700_000_000;
		expect(w()).toEqual([1_700_000_000, 1_700_000_060]);
	});

	it("matches clockWindow for the same clock and ttl", () => {
		const now = () => 1_700_000_123.9;
		expect(monotonicWindow(now, 120)()).toEqual(clockWindow(now, 120)());
	});
});
