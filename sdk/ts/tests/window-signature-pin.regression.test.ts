// signInbound signature-window regression pin (TypeScript side).
//
// signInbound sources (created, expires) from an injected Window (default
// clockWindow(()=>Date.now()/1000, ttlSec)). clockWindow MUST FLOOR so the produced
// @signature-params bytes are deterministic:
//   - given a fractional now, created = floor(now/1000), expires = created+ttl,
//     emitted verbatim in the Signature-Input parameters, in the profile's order;
//   - signInbound is byte-deterministic for a fixed key + fixed now (Ed25519);
//   - a ttl longer than MAX_SIGNATURE_LIFETIME is refused, not signed.
import { describe, it, expect } from "vitest";
import { signInbound } from "../core/sign.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { AGENT_DIRECTORY } from "./wba-fixtures.ts";

async function fixedAgentKey(): Promise<CryptoKeyPair> {
	return crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	]) as Promise<CryptoKeyPair>;
}

const TARGET = "https://edge.example/fora.v1/resource";
// A fractional-millisecond now: floor(1_700_000_000_500 / 1000) = 1_700_000_000.
const NOW_MS = 1_700_000_000_500;
const TTL_SEC = 300;
const EXPECT_CREATED = 1_700_000_000;
const EXPECT_EXPIRES = 1_700_000_300;

describe("signInbound signature window survives the Window refactor byte-identically", () => {
	it("floors created and stamps created/expires verbatim in Signature-Input", async () => {
		const kp = await fixedAgentKey();
		const rawPub = new Uint8Array(
			await crypto.subtle.exportKey("raw", kp.publicKey),
		);
		const agentId = await thumbprint(rawPub);

		const req = await signInbound(kp, TARGET, {
			signatureAgent: AGENT_DIRECTORY,
			now: () => NOW_MS,
			ttlSec: TTL_SEC,
		});
		const sigInput = req.headers.get("signature-input");
		expect(sigInput).toBe(
			`sig1=("@method" "@target-uri" "signature-agent";key="sig1");created=${EXPECT_CREATED};expires=${EXPECT_EXPIRES};keyid="${agentId}";alg="ed25519";tag="web-bot-auth"`,
		);
		expect(req.headers.get("signature-agent")).toBe(`sig1="${AGENT_DIRECTORY}"`);
	});

	it("refuses a window longer than MAX_SIGNATURE_LIFETIME", async () => {
		const kp = await fixedAgentKey();
		await expect(
			signInbound(kp, TARGET, { signatureAgent: AGENT_DIRECTORY, now: () => NOW_MS, ttlSec: 600 }),
		).rejects.toMatchObject({ reason: "signature_lifetime" });
	});

	it("is byte-deterministic for a fixed key + fixed now (identical signature)", async () => {
		const kp = await fixedAgentKey();
		const opts = { signatureAgent: AGENT_DIRECTORY, now: () => NOW_MS, ttlSec: TTL_SEC };
		const a = await signInbound(kp, TARGET, opts);
		const b = await signInbound(kp, TARGET, opts);
		expect(a.headers.get("signature-input")).toBe(b.headers.get("signature-input"));
		expect(a.headers.get("signature")).toBe(b.headers.get("signature"));
	});
});
