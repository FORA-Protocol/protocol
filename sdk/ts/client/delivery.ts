// Delivery verification: checking a signed retrieval URL before it is used.
//
// A purchase answers with a retrieval_endpoint per item: a URL the issuing Exchange
// signed over "GET\n<canonical URL>", carrying its expiry (`exp`), the key that signed it
// (`kid`, the thumbprint of the Exchange's URL-signing key) and, when the Exchange bound
// it, the agent it was issued to (`agent_id`). It is the one signed value in a result
// item — a Broker that relayed the purchase cannot forge or alter it — so the client
// checks it where it arrives instead of leaving the delivery edge to refuse it later.
//
// The Exchange's URL-signing keys come from its Web Bot Auth key directory, the same
// directory that publishes its other keys, resolved through the injected
// DeliveryKeyResolver (the SDK's WBA resolver by default).

import { retrievalAuthFailureDetail, type RetrievalAuthFailureReason } from "../src/errordetail.ts";
import { verifyEd25519SignedUrl, type VerifyFailure } from "../src/verify.ts";
import { DirectoryUnavailable } from "../resolvers/errors.ts";
import { ForaCallError } from "./errors.ts";

/** A retrieval URL whose signature, agent binding and expiry this client verified. */
export interface Delivery {
	/** The signed retrieval URL, verbatim. */
	url: string;
	/** The Exchange whose URL-signing key verified the signature. */
	exchange: string;
	/** The RFC 7638 thumbprint the URL is bound to; "" for a bearer (unbound) URL. */
	agentId: string;
	/** The `kid` that named the Exchange's URL-signing key. */
	keyId: string;
	/** When the URL expires (its `exp`). */
	expiresAt: Date;
}

/**
 * Resolves an Exchange's URL-signing key: the raw 32-byte Ed25519 public key whose RFC 7638
 * thumbprint is `thumbprint`, from the WBA directory of `directory` (the Exchange's bare
 * domain). The SDK's WBA resolver (createWBAKeyResolver) satisfies it. Undefined for a key
 * the directory does not publish; a thrown DirectoryUnavailable reads as a directory that
 * could not be reached.
 */
export interface DeliveryKeyResolver {
	resolve(thumbprint: string, directory: string): Promise<Uint8Array | undefined>;
}

/** The ErrorDetail domain for a refusal this client computed itself. */
const CLIENT_ERROR_DOMAIN = "fora.v1.Client";

const REASON_OF: Readonly<Record<VerifyFailure, RetrievalAuthFailureReason>> = {
	missing_sig: "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING",
	missing_exp: "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING",
	bad_exp_encoding: "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING",
	expired: "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED",
	bad_sig_encoding: "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH",
	signature_mismatch: "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH",
	bad_agent_encoding: "RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH",
};

/** What one verification is checked against. */
export interface DeliveryCheck {
	/** The verb, for the failure. */
	op: string;
	/** Which URL this is, in the failure's words ("item 0 (transaction tx-1)"). */
	subject: string;
	/** The Exchange whose key must verify the signature. */
	exchange: string;
	/** This agent's thumbprint; undefined when the client cannot know it. */
	agent: string | undefined;
	/** The agent_identity_hash the answer stated; "" or undefined when it stated none. */
	stated: string | undefined;
	keys: DeliveryKeyResolver;
	/** The clock, epoch milliseconds. */
	now: () => number;
}

/**
 * verifyDelivery checks one retrieval URL and returns the binding it verified, or throws
 * the typed refusal: `malformed` with a synthesized retrieval_auth_failure detail for a
 * URL that does not verify, `unreachable` when the Exchange's directory cannot be read.
 *
 * The binding rule: a URL carrying `agent_id` must name this agent, and an answer that
 * stated an agent_identity_hash must have bound the URL to exactly that. A bearer URL
 * (no `agent_id`) from an answer that stated none verifies, with `agentId` "".
 */
export async function verifyDelivery(url: string, check: DeliveryCheck): Promise<Delivery> {
	let unreachable: unknown;
	let keyId = "";
	let result: Awaited<ReturnType<typeof verifyEd25519SignedUrl>>;
	try {
		result = await verifyEd25519SignedUrl(url, {
			now: check.now,
			resolveKey: async (kid) => {
				if (kid === undefined) return undefined;
				keyId = kid;
				let raw: Uint8Array | undefined;
				try {
					raw = await check.keys.resolve(kid, check.exchange);
				} catch (cause) {
					if (cause instanceof DirectoryUnavailable) unreachable = cause;
					return undefined;
				}
				if (raw === undefined) return undefined;
				return crypto.subtle.importKey("raw", new Uint8Array(raw), "Ed25519", false, [
					"verify",
				]);
			},
		});
	} catch (cause) {
		// A value that does not parse as a URL is a URL no Exchange signed.
		throw refusal(check, "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH", cause);
	}
	if (unreachable !== undefined) {
		throw new ForaCallError({
			kind: "unreachable",
			op: check.op,
			cause: new Error(
				`${check.subject}: the key directory of ${check.exchange} could not be read`,
				{ cause: unreachable },
			),
		});
	}
	if (!result.valid) {
		const reason = result.reason ?? "signature_mismatch";
		throw refusal(check, REASON_OF[reason], new Error(reason));
	}
	const agentId = result.agentId ?? "";
	if (agentId !== "" && check.agent !== undefined && agentId !== check.agent) {
		throw refusal(
			check,
			"RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH",
			new Error(`bound to ${agentId}, not to this agent (${check.agent})`),
		);
	}
	const stated = check.stated ?? "";
	if (stated !== "" && agentId !== stated) {
		throw refusal(
			check,
			"RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH",
			new Error(`bound to ${JSON.stringify(agentId)}, the answer stated ${stated}`),
		);
	}
	return {
		url,
		exchange: check.exchange,
		agentId,
		keyId: result.kid ?? keyId,
		expiresAt: new Date(Number(new URL(url).searchParams.get("exp")) * 1000),
	};
}

function refusal(
	check: DeliveryCheck,
	reason: RetrievalAuthFailureReason,
	cause: unknown,
): ForaCallError {
	const why = cause instanceof Error ? cause.message : String(cause);
	return new ForaCallError({
		kind: "malformed",
		op: check.op,
		cause: new Error(`${check.subject}: the delivery URL does not verify: ${why}`),
		detail: retrievalAuthFailureDetail(
			CLIENT_ERROR_DOMAIN,
			"delivery URL failed the client's verification",
			reason,
		),
	});
}
