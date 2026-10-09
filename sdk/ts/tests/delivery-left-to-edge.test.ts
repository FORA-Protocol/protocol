// Delivery URLs are checked by the delivery edge, not by the agent's client.
//
// The edge verifies the URL signature and, where it can, the agent binding against the
// proof of possession the agent presents. An edge that cannot check the binding
// (CloudFront with its pre-arranged RSA key pair) checks its own signature and treats the
// URL as a bearer token. So execute and BrokerClient.execute return every URL exactly as
// the Exchange issued it, even one this client could not read, and fetch dials a URL as
// given with the proof attached. By the time the answer arrives the Exchange has charged,
// and refusing it locally would lose the purchase answer.
//
// The purchase verbs run through the injected send, as the other execute tests do; fetch
// dials a real loopback server.
import { createServer, type IncomingHttpHeaders } from "node:http";
import { describe, expect, it } from "vitest";

import { createBrokerClient, createClient, type ClientOptions } from "../client/index.ts";
import { createVerifier, type VerifiedOffer } from "../core/verifier.ts";
import { signOffer } from "../src/offer-sign.ts";
import { signEd25519SignedUrl } from "../src/signurl.ts";

const REQUESTER = { id: "agent-1", domain: "agent.test", type: "REQUESTER_TYPE_AGENT" };
const CLOUDFRONT_QUERY = "?Expires=4102444800&Signature=c2lnbmF0dXJl&Key-Pair-Id=K2JCJMDEHXQW5F";
/** A CloudFront RSA signed URL: no kid, no agent_id, a signature no Ed25519 check reads. */
const CLOUDFRONT_URL = `https://d111111abcdef8.cloudfront.net/content/asset-2${CLOUDFRONT_QUERY}`;

async function keyPair(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

/** Signed by a key no directory publishes, bound to another agent, already expired. */
async function unverifiableURL(): Promise<string> {
	return signEd25519SignedUrl(
		"https://edge.example/content/asset-1",
		{ kid: "unknown-key", agentId: "someone-else", expUnix: 1 },
		(await keyPair()).privateKey,
	);
}

async function offerAt(id: string, exchange: string): Promise<VerifiedOffer> {
	const kp = await keyPair();
	const publicKey = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	) as Uint8Array<ArrayBuffer>;
	const unsigned: Record<string, unknown> = {
		offer_id: id,
		exchange,
		expires_at: "2099-01-01T00:00:00Z",
	};
	const offer = {
		...unsigned,
		signature: await signOffer(unsigned, kp.privateKey),
		signature_algorithm: "EdDSA",
	};
	const sorted = await createVerifier("strict", {
		resolve: async () => publicKey,
		now: () => Date.parse("2024-01-01T00:00:00Z"),
	}).sort([offer]);
	const verified = sorted.verified[0];
	if (verified === undefined) throw new Error("fixture offer did not verify");
	return verified;
}

async function options(answer: unknown, sent: { count: number }): Promise<ClientOptions> {
	const keys = await keyPair();
	return {
		requester: REQUESTER,
		signer: { privKey: keys.privateKey, keyid: "agent.v1" },
		agentPublicKey: keys.publicKey,
		signatureAgent: "https://agent.test",
		send: async () => {
			sent.count++;
			return { status: 200, body: JSON.stringify(answer) };
		},
	};
}

function items(urls: string[]) {
	return urls.map((url, i) => ({
		offer_id: `offer-${i}`,
		transaction_id: `tx-${i}`,
		retrieval_endpoint: url,
	}));
}

describe("a purchase returns every delivery URL as issued", () => {
	it("Client.execute", async () => {
		const urls = [await unverifiableURL(), CLOUDFRONT_URL];
		const sent = { count: 0 };
		const answer = { ver: "1.0", agent_identity_hash: "agent-thumbprint", items: items(urls) };
		const client = createClient("https://exchange.test", await options(answer, sent));
		const offers = [await offerAt("offer-0", "exchange.test"), await offerAt("offer-1", "exchange.test")];

		const result = await client.execute(offers);

		expect(result.items?.map((i) => i.retrieval_endpoint)).toEqual(urls);
		// One round trip, the purchase: no key directory is read.
		expect(sent.count).toBe(1);
	});

	it("BrokerClient.execute", async () => {
		const urls = [await unverifiableURL(), CLOUDFRONT_URL];
		const sent = { count: 0 };
		const answer = {
			ver: "1.0",
			items: items(urls),
			exchanges: [
				{ exchange: "exchange-a.test", offer_ids: ["offer-0"] },
				{ exchange: "exchange-b.test", offer_ids: ["offer-1"] },
			],
		};
		const client = createBrokerClient("https://broker.test", await options(answer, sent));
		const offers = [await offerAt("offer-0", "exchange-a.test"), await offerAt("offer-1", "exchange-b.test")];

		const result = await client.execute(offers);

		expect(result.items?.map((i) => i.retrieval_endpoint)).toEqual(urls);
		expect(sent.count).toBe(1);
	});
});

describe("fetch dials the URL as given with the agent's proof", () => {
	it("sends a CloudFront URL to the edge, proof attached", async () => {
		const seen: { url?: string | undefined; headers?: IncomingHttpHeaders } = {};
		const server = createServer((req, res) => {
			seen.url = req.url;
			seen.headers = req.headers;
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("body");
		});
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
		const port = (server.address() as { port: number }).port;
		const saved = [process.env["SKIP_SSRF"], process.env["ALLOW_INSECURE"]];
		process.env["SKIP_SSRF"] = "true";
		process.env["ALLOW_INSECURE"] = "true";
		try {
			const client = createClient("https://exchange.test", await options({}, { count: 0 }));
			const content = await client.fetch(
				`http://127.0.0.1:${port}/content/asset-2${CLOUDFRONT_QUERY}`,
			);
			expect(new TextDecoder().decode(content.body)).toBe("body");
			expect(seen.url).toBe(`/content/asset-2${CLOUDFRONT_QUERY}`);
			expect(seen.headers?.["x-fora-agent-key"]).toBeTruthy();
			expect(seen.headers?.["signature"]).toBeTruthy();
		} finally {
			if (saved[0] === undefined) delete process.env["SKIP_SSRF"];
			else process.env["SKIP_SSRF"] = saved[0];
			if (saved[1] === undefined) delete process.env["ALLOW_INSECURE"];
			else process.env["ALLOW_INSECURE"] = saved[1];
			server.close();
		}
	});
});
