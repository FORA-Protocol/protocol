// Mint an Ed25519 identity a FORA verifier can resolve.
//
// Four steps a caller otherwise assembles by hand: a key and its keyid, the Web Bot Auth
// key directory that publishes it, the response signatures that directory is served
// with, and a signer that signs as it. The directory has the shape of the generated
// WBAFile schema, the one the SDK's own WBA resolver parses, and a resolver hands out
// only the keys whose signature the response carries, so a directory is served as
//
//	const body = new TextEncoder().encode(JSON.stringify(await directoryDocument([pub])));
//	const sig = await signDirectoryResponse("agent.example", body, [{ privKey, keyid }], created, expires);
//
// with Content-Type WBA_DIRECTORY_MEDIA_TYPE and sig's three headers.

import type { z } from "zod";

import type { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import { encodeBase64Url } from "../src/base64url.ts";
import { exportRawPublicKey, thumbprint } from "../src/thumbprint.ts";
import { createSigningTransport, type OutboundSend } from "./signing-transport.ts";

export {
	type DirectoryResponseSignature,
	type DirectoryResponseSigner,
	DirectoryResponseError,
	type ResponseHeaders,
	signDirectoryResponse,
	verifyDirectoryResponse,
} from "./directory-response.ts";

/** A Web Bot Auth key directory document. */
export type WBAFile = z.infer<typeof WBAFileSchema>;

/** How long a published key stays valid by default: 365 days, in milliseconds. */
export const DEFAULT_KEY_VALIDITY_MS = 365 * 24 * 60 * 60 * 1000;

/** How far before "now" a published key's validity window opens, so a verifier whose
 * clock runs slightly behind still accepts it. */
const NOT_BEFORE_MARGIN_MS = 5 * 60 * 1000;

/**
 * generateKey returns a fresh Ed25519 key pair and its RFC 7638 thumbprint: the keyid every
 * FORA signature names. The private key is non-extractable; the public key can always be
 * exported.
 */
export async function generateKey(): Promise<{ keyPair: CryptoKeyPair; thumbprint: string }> {
	const keyPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	return { keyPair, thumbprint: await thumbprint(await exportRawPublicKey(keyPair.publicKey)) };
}

/**
 * directoryDocument returns the Web Bot Auth key-directory JSON publishing `keys` (Ed25519
 * public keys), in order.
 *
 * Each key keeps JWK alg "EdDSA", the RFC 7517 name for the algorithm, not the RFC 9421
 * value "ed25519" a signature names. Each key carries the `not_before` / `not_after`
 * window the resolver requires before it will hand the key out: it opens five minutes before `now` and lasts `validForMs`
 * (DEFAULT_KEY_VALIDITY_MS when absent or not positive). `now` defaults to the current time
 * and is injectable for a deterministic document. No revocation_url is set.
 */
export async function directoryDocument(
	keys: readonly CryptoKey[],
	opts: { validForMs?: number; now?: Date } = {},
): Promise<WBAFile> {
	const now = (opts.now ?? new Date()).getTime();
	const validFor =
		opts.validForMs !== undefined && opts.validForMs > 0 ? opts.validForMs : DEFAULT_KEY_VALIDITY_MS;
	const notBefore = new Date(now - NOT_BEFORE_MARGIN_MS).toISOString();
	const notAfter = new Date(now + validFor).toISOString();
	return {
		keys: await Promise.all(
			keys.map(async (key) => ({
				kty: "OKP",
				crv: "Ed25519",
				alg: "EdDSA",
				use: "sig",
				x: encodeBase64Url(await exportRawPublicKey(key)),
				not_before: notBefore,
				not_after: notAfter,
			})),
		),
	} as WBAFile;
}

/**
 * signingTransportFor returns a signing transport that signs as `keyPair`: keyid is its
 * public key's thumbprint and each signature's Signature-Agent member names `directory`,
 * the https origin ("https://agent.example") of the key directory that publishes it. It
 * wraps `send` exactly as createSigningTransport does.
 */
export async function signingTransportFor<R>(
	keyPair: CryptoKeyPair,
	directory: string,
	send: OutboundSend<R>,
): Promise<OutboundSend<R>> {
	return createSigningTransport(send, {
		privKey: keyPair.privateKey,
		keyid: await thumbprint(await exportRawPublicKey(keyPair.publicKey)),
		signatureAgent: directory,
	});
}
