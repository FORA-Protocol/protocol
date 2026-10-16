// The directory reads judge a directory's response signatures at a clock.
//
// readWBADirectory takes it as `now`, and so does createWBAOfferDirectoryFetch, which
// reads it on every fetch, so the offer-key cache that selects keys and the fetch that
// checks the directory can run on one clock. Each case serves a directory whose response
// signature is good only inside a narrow window long before the wall clock.
import { describe, expect, it } from "vitest";
import {
	createCachedOfferKeyResolver,
	createWBAOfferDirectoryFetch,
	DirectoryResponseUnsigned,
	type FetchLike,
	readWBADirectory,
} from "../resolvers/edge.ts";
import { HOUR_MS, iso, makeKey, signedDirectoryHeaders, type TestKey, wbaFileJson, wbaJwk } from "./resolvers-harness.ts";

const AUTHORITY = "pub.example";
const DIRECTORY_URL = `https://${AUTHORITY}/.well-known/http-message-signatures-directory`;
const CREATED = 1_000_000_000; // unix seconds
const EXPIRES = CREATED + 60;
const IN_WINDOW_MS = (CREATED + 30) * 1000;

// serve answers the directory URL with one key, valid around IN_WINDOW_MS, whose response
// signature is good only inside [CREATED, EXPIRES].
async function serve(): Promise<{ key: TestKey; fetch: FetchLike }> {
	const key = await makeKey();
	const body = wbaFileJson([wbaJwk(key.x, iso(IN_WINDOW_MS - HOUR_MS), iso(IN_WINDOW_MS + HOUR_MS))]);
	const headers = await signedDirectoryHeaders(AUTHORITY, body, undefined, { created: CREATED, expires: EXPIRES });
	const fetch: FetchLike = async (url) =>
		url === DIRECTORY_URL ? new Response(body, { headers }) : new Response("", { status: 404 });
	return { key, fetch };
}

describe("readWBADirectory", () => {
	it("judges the response signatures at `now`, and at the wall clock by default", async () => {
		const { key, fetch } = await serve();
		const doc = await readWBADirectory(AUTHORITY, { fetch, now: () => IN_WINDOW_MS });
		expect(doc.message.keys?.map((k) => k.x)).toEqual([key.x]);
		await expect(readWBADirectory(AUTHORITY, { fetch })).rejects.toBeInstanceOf(DirectoryResponseUnsigned);
	});
});

describe("createWBAOfferDirectoryFetch", () => {
	it("judges the response signatures at `now`, read on every fetch", async () => {
		const { key, fetch } = await serve();
		expect((await createWBAOfferDirectoryFetch({ fetch })(AUTHORITY))?.keys ?? []).toHaveLength(0);
		let now = IN_WINDOW_MS;
		const read = createWBAOfferDirectoryFetch({ fetch, now: () => now });
		expect((await read(AUTHORITY))?.keys?.map((k) => k.x)).toEqual([key.x]);
		now = (EXPIRES + 1) * 1000;
		expect((await read(AUTHORITY))?.keys ?? []).toHaveLength(0);
	});

	it("shares one clock with the offer-key cache", async () => {
		const { key, fetch } = await serve();
		const now = (): number => IN_WINDOW_MS;
		const shared = createCachedOfferKeyResolver({ fetch: createWBAOfferDirectoryFetch({ fetch, now }), now });
		expect(await shared.resolve(AUTHORITY)).toEqual(key.rawPub);
		const split = createCachedOfferKeyResolver({ fetch: createWBAOfferDirectoryFetch({ fetch }), now });
		expect(await split.resolve(AUTHORITY)).toBeUndefined();
	});

	it("contains a clock that throws as undefined", async () => {
		const { fetch } = await serve();
		const read = createWBAOfferDirectoryFetch({
			fetch,
			now: () => {
				throw new Error("no clock");
			},
		});
		expect(await read(AUTHORITY)).toBeUndefined();
	});
});
