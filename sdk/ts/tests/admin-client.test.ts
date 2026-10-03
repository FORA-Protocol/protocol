// The operator client: createAdminClient covers every fora.admin.v1.AdminService RPC and
// the two domain-verification RPCs of ExchangeService.
//
// The RPC list is read from the proto files rather than written here, so an RPC added to
// AdminService fails this suite until the client has a verb for it. Each verb is driven
// through the injected send against a peer that verifies the signature.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
	createAdminClient,
	ForaCallError,
	RawBody,
	type AdminClient,
	type UnaryRequest,
} from "../client/index.ts";
import { agentKeys, signedPeer } from "./signed-peer.ts";

const PROTO = fileURLToPath(new URL("../../../proto/", import.meta.url));

/** The RPC names a service declares in a proto file. */
function rpcsOf(file: string, service: string): string[] {
	const text = readFileSync(`${PROTO}${file}`, "utf8");
	const start = text.indexOf(`service ${service} {`);
	if (start < 0) throw new Error(`${service} not found in ${file}`);
	const body = text.slice(start, text.indexOf("\n}", start));
	return [...body.matchAll(/^\s*rpc (\w+)\(/gm)].map((m) => m[1] as string);
}

const ADMIN_RPCS = rpcsOf("fora/admin/v1/admin.proto", "AdminService");
const DOMAIN_RPCS = rpcsOf("fora/v1/fora.proto", "ExchangeService").filter((n) =>
	n.endsWith("DomainVerification"),
);

const verbOf = (rpc: string) => `${rpc[0]?.toLowerCase()}${rpc.slice(1)}` as keyof AdminClient;

/** A valid request and a valid answer per RPC. */
const CALLS: Record<string, { request: Record<string, unknown>; answer: Record<string, unknown> }> = {
	SetTenantFeeRate: {
		request: { rate: { tenant_id: "t-1", fee_rate_bps: 250 } },
		answer: { ver: "1.0", rate: { tenant_id: "t-1", fee_rate_bps: 250 } },
	},
	SetReportingPolicy: {
		request: { policy: { tenant_id: "t-1", required_fields: ["tokens"], window_seconds: 3600 } },
		answer: { ver: "1.0", policy: { tenant_id: "t-1", required_fields: ["tokens"], window_seconds: 3600 } },
	},
	RequestDomainVerification: {
		request: { exchange: "exchange.test", domain: "publisher.test" },
		answer: { ver: "1.0", token: "tok", verification_url: "https://publisher.test/.well-known/fora-verify/tok" },
	},
	ConfirmDomainVerification: {
		request: { exchange: "exchange.test", domain: "publisher.test", token: "tok" },
		answer: { ver: "1.0", key_id: "k-1" },
	},
};

async function fixture() {
	const { keys, pub } = await agentKeys();
	const peer = signedPeer("operator.v1", pub, (req: UnaryRequest) => {
		const rpc = req.url.slice(req.url.lastIndexOf("/") + 1);
		return { status: 200, body: JSON.stringify(CALLS[rpc]?.answer ?? {}) };
	});
	const client = createAdminClient("https://admin.exchange.test", {
		signer: { privKey: keys.privateKey, keyid: "operator.v1" },
		send: peer.send,
	});
	return { peer, client };
}

describe("AdminClient", () => {
	it("the proto declares the RPCs this suite covers", () => {
		expect(ADMIN_RPCS.length).toBeGreaterThan(0);
		expect(DOMAIN_RPCS).toEqual(["RequestDomainVerification", "ConfirmDomainVerification"]);
	});

	for (const [service, rpcs] of [
		["fora.admin.v1.AdminService", ADMIN_RPCS],
		["fora.v1.ExchangeService", DOMAIN_RPCS],
	] as const) {
		for (const rpc of rpcs) {
			it(`${service}/${rpc}`, async () => {
				const call = CALLS[rpc];
				if (call === undefined) throw new Error(`no fixture for ${rpc}: add one when the RPC is added`);
				const { peer, client } = await fixture();
				const verb = client[verbOf(rpc)];
				expect(typeof verb, `AdminClient has no ${verbOf(rpc)}`).toBe("function");
				const answer = await (verb as (r: unknown) => Promise<unknown>)(call.request);
				const received = peer.only();
				expect(received.request.url).toBe(`https://admin.exchange.test/${service}/${rpc}`);
				expect(received.valid).toBe(true);
				expect(JSON.parse(received.body)).toEqual({ ver: "1.0", ...call.request });
				expect(answer).toMatchObject(call.answer);
			});
		}
	}

	it("refuses a domain-verification request that names no recipient", async () => {
		const { peer, client } = await fixture();
		await expect(client.requestDomainVerification({ domain: "publisher.test" })).rejects.toMatchObject({
			kind: "not_sent",
		});
		await expect(
			client.confirmDomainVerification({ exchange: "https://exchange.test", domain: "p", token: "t" }),
		).rejects.toMatchObject({ kind: "not_sent" });
		expect(peer.seen).toHaveLength(0);
	});

	it("refuses a request its generated schema rejects, before signing it", async () => {
		const { peer, client } = await fixture();
		const f = await client.setTenantFeeRate({ rate: { tenant_id: "t-1", fee_rate_bps: 10000 } }).catch((e: unknown) => e);
		expect(f).toBeInstanceOf(ForaCallError);
		expect((f as ForaCallError).kind).toBe("malformed");
		expect(peer.seen).toHaveLength(0);
	});

	it("sends a RawBody as given", async () => {
		const { peer, client } = await fixture();
		await client.setReportingPolicy(new RawBody('{"policy":{}}'));
		expect(peer.only().body).toBe('{"policy":{}}');
	});

	it("surfaces the Exchange's refusal as a typed failure", async () => {
		const client = createAdminClient("https://admin.exchange.test", {
			send: async () => ({
				status: 412,
				body: JSON.stringify({
					code: "failed_precondition",
					message: "challenge not found",
					details: [
						{
							type: "fora.v1.ErrorDetail",
							debug: {
								domain: "fora.v1.ExchangeService",
								domainVerificationFailure: { reason: "DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_NOT_FOUND" },
							},
						},
					],
				}),
			}),
		});
		const f = (await client
			.confirmDomainVerification(CALLS["ConfirmDomainVerification"]?.request ?? {})
			.then(
				() => undefined,
				(e: unknown) => e,
			)) as ForaCallError;
		expect(f).toBeInstanceOf(ForaCallError);
		expect(f.kind).toBe("refused");
		expect(f.code).toBe("failed_precondition");
		expect(f.detail?.domain_verification_failure?.reason).toBe(
			"DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_NOT_FOUND",
		);
	});
});
