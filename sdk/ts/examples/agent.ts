// The worked TypeScript agent example the documentation site shows.
//
// The site does not keep its own copy of this code. Every TypeScript block on the
// agent-SDK pages is a REGION of this file, pulled in at build time by
// website/plugins/remark-example.mjs, so what a reader copies is what the compiler
// checked. The hand-kept copy that lived on the site read `content.length` on a
// Content that has no `length`, which made the usage report bill nothing, and nothing
// on the site could catch it.
//
// Regions are delimited by "fora:example <name>" / "fora:/example <name>" comments.
// The marker lines never reach the page.
//
// This file is type-checked by `tsc -p tsconfig.json --strict --noEmit`, which runs as
// part of `npm test` here and in sdk-types-ci.yml. It is NOT part of the published
// package: scripts/build.mjs stages src, core, client, hono and resolvers only.
//
// The imports name the package by its PUBLISHED specifier rather than by a relative
// path, because that is what a reader installs. tsconfig.json maps those specifiers
// back to this tree so the check is real.

// fora:example imports
import { createClient } from "@fora-protocol/sdk/client";
import { rejectedOffers, verifiedOffers } from "@fora-protocol/sdk/core";
import {
	createCachedOfferKeyResolver,
	createWBAOfferDirectoryFetch,
	createWellKnownEndpointResolver,
} from "@fora-protocol/sdk/resolvers";
// fora:/example imports

/**
 * buy fetches one URL through the four shipped verbs and reports what it used.
 *
 * The identity arguments are what a real agent holds. They are parameters rather than
 * globals because the SDK takes every one of them as an injected seam: the private key
 * is a non-extractable CryptoKey whose bytes never enter the SDK.
 */
export async function buy(
	baseURL: string,
	privKey: CryptoKey,
	keyid: string,
	agentPublicKey: CryptoKey,
	requester: Record<string, unknown>,
): Promise<void> {
	// fora:example client
	// Offer-signing keys come from the issuing Exchange's Web Bot Auth directory --
	// the only place they are published. The directory fetch is SSRF-guarded by
	// default, because the exchange domain arrives inside an offer.
	const offerKeys = createCachedOfferKeyResolver({
		fetch: createWBAOfferDirectoryFetch({}),
	});

	const client = createClient(baseURL, {
		signer: { privKey, keyid }, // a non-extractable CryptoKey; key bytes never enter the SDK
		agentPublicKey, // the public half a bound delivery fetch presents
		requester, // who this agent says it is
		resolveOfferKey: async (exchange) => offerKeys.resolve(exchange),
		endpointResolver: createWellKnownEndpointResolver({}),
	});
	// fora:/example client

	// fora:example discover
	// 1. Discover. Offers arrive already sorted into verified and rejected, and a
	//    rejected one keeps the reason it was refused.
	const found = await client.discover({
		exchange: "exchange.example",
		uris: ["https://publisher.example/article"],
		// Which domains you work in is a property of the query rather than of the
		// client, so it goes here.
		supported_profiles: [
			"fora-news-v1", // articles, podcasts, broadcasting
			"fora-academic-v1", // journal papers, preprints, datasets
			"fora-legal-v1", // legislation, case law, patents
		],
	});
	const offers = verifiedOffers(found);
	if (offers.length === 0) {
		throw new Error(`no verifiable offer: ${JSON.stringify(rejectedOffers(found))}`);
	}
	// fora:/example discover

	// fora:example execute
	// 2. Buy. Execute accepts only a verified offer, so an unverified one cannot be
	//    paid for by mistake.
	const tx = await client.execute(offers[0]!);
	const item = tx.items?.[0];
	if (!item?.retrieval_endpoint) {
		throw new Error("the Exchange delivered no retrieval endpoint");
	}
	// fora:/example execute

	// fora:example fetch
	// 3. Fetch. The delivery URL is bound to the agent's key and the client presents
	//    the matching proof of possession, so a copied link fetches nothing.
	const content = await client.fetch(item.retrieval_endpoint);
	// fora:/example fetch

	// fora:example report
	// 4. Report what was used. consumed_quantity is the billed quantity, so a report
	//    without `usage` bills nothing. Content.body holds the fetched bytes.
	//    `function` is optional and is omitted here: the published package exposes no
	//    vocabulary entry point, and a token spelled by hand is exactly what the typed
	//    constants exist to prevent.
	await client.reportUsage({
		exchange: "exchange.example",
		transaction_id: item.transaction_id,
		billing_id: item.billing_id,
		usage: { consumed_quantity: content.body.length },
	});
	// fora:/example report
}
