// Mint an Ed25519 identity a FORA verifier can resolve.
//
// Three steps a caller otherwise assembles by hand: a key and its keyid, the Web Bot Auth
// key directory that publishes it, and a signer that signs as it. The directory has the
// shape of the generated WBAFile schema, the one the SDK's own WBA resolver parses, so a
// document built here is one that resolver accepts.

import type { z } from "zod";

import type { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import { encodeBase64Url } from "../src/base64url.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { createSigningTransport, type OutboundSend } from "./signing-transport.ts";

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
	return { keyPair, thumbprint: await thumbprint(await rawPublic(keyPair.publicKey)) };
}

/**
 * directoryDocument returns the Web Bot Auth key-directory JSON publishing `keys` (Ed25519
 * public keys), in order.
 *
 * Each key carries the `not_before` / `not_after` window the resolver requires before it
 * will hand the key out: it opens five minutes before `now` and lasts `validForMs`
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
				x: encodeBase64Url(await rawPublic(key)),
				not_before: notBefore,
				not_after: notAfter,
			})),
		),
	} as WBAFile;
}

/**
 * signingTransportFor returns a signing transport that signs as `keyPair`: keyid is its
 * public key's thumbprint and Signature-Agent is `directory`, the WBA directory that
 * publishes it. It wraps `send` exactly as createSigningTransport does.
 */
export async function signingTransportFor<R>(
	keyPair: CryptoKeyPair,
	directory: string,
	send: OutboundSend<R>,
): Promise<OutboundSend<R>> {
	return createSigningTransport(send, {
		privKey: keyPair.privateKey,
		keyid: await thumbprint(await rawPublic(keyPair.publicKey)),
		signatureAgent: directory,
	});
}

async function rawPublic(key: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}
