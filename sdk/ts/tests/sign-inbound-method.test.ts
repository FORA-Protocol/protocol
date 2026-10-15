// signInbound signs the HTTP method it is given (Go PoPOptions.Method): upper-cased into
// the base as @method, GET when unset, and set on the returned Request. A proof made for
// one method verifies through verifyAgentBinding for that method only.

import { describe, expect, it } from "vitest";
import { signInbound } from "../core/sign.ts";
import { verifyAgentBinding } from "../src/pop.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { AGENT_DIRECTORY } from "./wba-fixtures.ts";

async function agent(): Promise<{ kp: CryptoKeyPair; agentId: string; url: string }> {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const agentId = await thumbprint(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
	return { kp, agentId, url: `https://cdn.example/a%2Fb/doc?agent_id=${agentId}` };
}

describe("signInbound signs the method it is given", () => {
	it("a HEAD proof round-trips through verifyAgentBinding as HEAD", async () => {
		const { kp, agentId, url } = await agent();
		const req = await signInbound(kp, url, { signatureAgent: AGENT_DIRECTORY, method: "HEAD" });
		expect(req.method).toBe("HEAD");
		const res = await verifyAgentBinding({ url, method: req.method, headers: req.headers, agentId });
		expect(res).toEqual({ ok: true, signatureAgent: AGENT_DIRECTORY });
	});

	it("refuses a HEAD proof verified as GET, and a GET proof verified as HEAD", async () => {
		const { kp, agentId, url } = await agent();
		const head = await signInbound(kp, url, { signatureAgent: AGENT_DIRECTORY, method: "HEAD" });
		const asGet = await verifyAgentBinding({ url, method: "GET", headers: head.headers, agentId });
		expect(asGet).toEqual({ ok: false, reason: "pop_sig_invalid" });
		const get = await signInbound(kp, url, { signatureAgent: AGENT_DIRECTORY });
		const asHead = await verifyAgentBinding({ url, method: "HEAD", headers: get.headers, agentId });
		expect(asHead).toEqual({ ok: false, reason: "pop_sig_invalid" });
	});

	it("upper-cases the method into the base, so a lowercase method verifies as its uppercase form", async () => {
		const { kp, agentId, url } = await agent();
		const req = await signInbound(kp, url, { signatureAgent: AGENT_DIRECTORY, method: "head" });
		expect(req.method).toBe("HEAD");
		const res = await verifyAgentBinding({ url, method: "HEAD", headers: req.headers, agentId });
		expect(res.ok).toBe(true);
	});

	it("signs GET when the method is unset or empty", async () => {
		const { kp, agentId, url } = await agent();
		for (const opts of [{}, { method: "" }]) {
			const req = await signInbound(kp, url, { signatureAgent: AGENT_DIRECTORY, ...opts });
			expect(req.method).toBe("GET");
			expect((await verifyAgentBinding({ url, method: "GET", headers: req.headers, agentId })).ok).toBe(true);
		}
	});

	it("refuses a method carrying a control byte before signing", async () => {
		const { kp, url } = await agent();
		await expect(signInbound(kp, url, { signatureAgent: AGENT_DIRECTORY, method: "GE\nT" })).rejects.toThrow(
			"method carries a control byte at byte 2",
		);
	});
});
