import { thumbprint } from "./thumbprint.ts";
import { AgentKeyHeader, SignatureAgentHeader, WBATag } from "./wire.ts";
import { decodeBase64Url, utf8Bytes } from "./base64url.ts";
import { opaqueUrl } from "./opaque-url.ts";
import { parseSignatureHeaders, type ParsedSignature } from "../core/multisig-parse.ts";
import { buildSignatureBase, ComponentUnavailable, requestComponentValue } from "../core/sign-request.ts";
import { keyed, plain, renderComponent, signatureDirectory } from "../core/wba.ts";

// Proof-of-possession verification for delivery-URL identity binding (ADR-013),
// relocated from the app edge (src/edge/src/pop.ts) as a pure L1 helper.
//
// When a signed URL carries an `agent_id` (the agent's RFC 7638 thumbprint), a
// code-capable edge requires the fetcher to prove possession of the bound key —
// fully offline. The proof is a full Web Bot Auth signature over the fetch:
//
//   1. the raw Ed25519 public key in `X-FORA-Agent-Key`,
//   2. a Signature-Agent member naming the agent's key directory, and
//   3. an RFC 9421 signature with tag="web-bot-auth" covering AT LEAST `@method`,
//      `@target-uri` and that member. A proof made by a Web Bot Auth library that
//      covers more, `@authority` or a header for example, verifies too,
//
// and the edge enforces the 3-way identity:
//
//   agent_id (URL) == keyid (Signature-Input) == thumbprint(presented key)
//
// The last equality is the one that cannot be dropped: verifying against the presented
// key alone proves nothing, since any actor could present their own key plus a valid
// self-signature. A generic WBA verifier ignores X-FORA-Agent-Key, resolves the same
// key from the directory the Signature-Agent member names, and accepts the same
// signature.
//
// The Ed25519 verify primitive is INJECTABLE (input.verifyEd25519) so a runtime
// without WebCrypto Ed25519 (Fastly Compute) can supply its own — the byte
// contract is the signature base, not the primitive. The default primitive is
// WebCrypto crypto.subtle. Byte-parity guard: the pop vectors are produced by the
// sdk/go signer (helpers.SignAgentBinding), and their verdicts, refusal tokens and
// Accept-Signature values by the sdk/go verifier (helpers.VerifyAgentBinding), which
// verifyAgentBinding ports check for check.

export const AGENT_KEY_HEADER = AgentKeyHeader.toLowerCase();

const ED25519_PUBLIC_KEY_BYTES = 32;

export type PopFailure =
  | "missing_agent_key"
  | "bad_agent_key"
  | "missing_sig"
  | "malformed_sig_input"
  | "unsupported_alg"
  | "bad_tag"
  | "bad_covered_components"
  | "bad_signature_agent"
  | "keyid_mismatch"
  | "thumbprint_mismatch"
  | "pop_missing_created"
  | "pop_future_created"
  | "pop_missing_exp"
  | "pop_expired"
  | "pop_sig_invalid";

export interface PopResult {
  ok: boolean;
  reason?: PopFailure;
  /** The https origin of the agent's key directory the proof's Signature-Agent member
   * names, set when the proof verifies. */
  signatureAgent?: string;
  /** The Accept-Signature value (RFC 9421 §5.1, WG-00 §5.3) a refusal is answered with:
   * POP_ACCEPT_SIGNATURE, set when the fetcher can fix the refusal by signing again as
   * the profile requires: no signature, a missing or wrong tag, a covered set missing a
   * required component, a Signature-Agent in a form the profile refuses, or a
   * Signature-Agent member that is not an https origin. Unset for every other refusal. */
  acceptSignature?: string;
}

/** The Accept-Signature value a refused delivery proof is answered with: the three
 * components a proof must cover at least, the dictionary form of Signature-Agent, and
 * the created, expires and tag parameters. The same value as Go
 * helpers.PoPAcceptSignature. */
export const POP_ACCEPT_SIGNATURE = `sig1=(${[plain("@method"), plain("@target-uri"), keyed("signature-agent", "sig1")]
  .map(renderComponent)
  .join(" ")});created;expires;tag="${WBATag}"`;

/**
 * Ed25519 verify primitive: (publicKey, signature, message) -> valid?. Injected
 * so non-WebCrypto runtimes can supply their own without changing the byte
 * contract. Defaults to WebCrypto. Byte params are `Uint8Array<ArrayBuffer>`
 * (never SharedArrayBuffer-backed) so the default can hand them to WebCrypto's
 * BufferSource without casts.
 */
export type Ed25519Verify = (
  publicKey: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>,
  message: Uint8Array<ArrayBuffer>,
) => Promise<boolean>;

export interface PopInput {
  /** Full request URL exactly as the request line carried it — the value the agent
   * signed as `@target-uri`, used verbatim. */
  url: string;
  /** The request method; upper-cased into the base as `@method`. */
  method: string;
  headers: Headers;
  /** The bound thumbprint carried in the URL's `agent_id` param. */
  agentId: string;
  /** Milliseconds since the epoch; defaults to Date.now. */
  now?: () => number;
  /** Optional Ed25519 verify primitive; defaults to WebCrypto crypto.subtle. */
  verifyEd25519?: Ed25519Verify;
}

const okResult = (signatureAgent: string): PopResult => ({ ok: true, signatureAgent });
const fail = (reason: PopFailure): PopResult => ({ ok: false, reason });
const failAccept = (reason: PopFailure): PopResult => ({
  ok: false,
  reason,
  acceptSignature: POP_ACCEPT_SIGNATURE,
});

/**
 * Verify the agent's proof of possession of the key bound to `agentId`.
 * Returns `{ ok: true }` only when the presented key, the Web Bot Auth signature,
 * and the 3-way identity all check out. The checks run in Go
 * helpers.VerifyAgentBinding's order, so the first failing check names the refusal
 * the same way in every SDK.
 */
export async function verifyAgentBinding(input: PopInput): Promise<PopResult> {
  const presented = readPresentedKey(input.headers);
  if (!presented.ok) return presented.result;

  const parsed = parseProof(input.headers);
  if (!parsed.ok) return parsed.result;
  const { sig, count } = parsed;
  // alg is an early reject only; the verify primitive is hard-pinned to Ed25519,
  // so alg is never a key/algorithm SELECTION input (no downgrade possible).
  if (sig.alg === undefined || sig.alg.toLowerCase() !== "ed25519") return fail("unsupported_alg");
  if (sig.tag !== WBATag) return failAccept("bad_tag");
  if (!coversTheProfile(sig)) return failAccept("bad_covered_components");
  const directory = signatureDirectory(input.headers.get(SignatureAgentHeader) ?? undefined, sig, count);
  if (!directory.ok) {
    // A covered member the request does not carry is a missing component; every other
    // refusal of the member, including a value that is not an https origin, is one the
    // fetcher fixes by naming its directory as the profile requires.
    return directory.refusal.kind === "missing_component"
      ? failAccept("bad_covered_components")
      : failAccept("bad_signature_agent");
  }

  // 3-way identity. keyid and the presented-key thumbprint must both equal the
  // URL-bound agent_id before any signature work is trusted.
  if (sig.keyid !== input.agentId) return fail("keyid_mismatch");
  const presentedThumb = await thumbprint(presented.key);
  if (presentedThumb !== input.agentId) return fail("thumbprint_mismatch");

  const stale = freshnessFailure(sig, input.now);
  if (stale) return fail(stale);

  const base = proofBase(input, sig);
  if (base === undefined) return failAccept("bad_covered_components");
  const verify = input.verifyEd25519 ?? defaultVerifyEd25519;
  const valid = await verify(presented.key, sig.signature, utf8Bytes(base));
  return valid ? okResult(directory.value) : fail("pop_sig_invalid");
}

// proofBase rebuilds the proof's signature base in its covered order, or undefined
// when the request cannot supply a component the proof covers. @method is the method
// upper-cased and @target-uri the URL verbatim, the bytes the request line carried;
// every other component, @authority or a header for example, is read the way a
// request signature reads it.
function proofBase(input: PopInput, sig: ParsedSignature): string | undefined {
  // Coerce a URL-like input (Fastly hands a URL object, not a string) to its
  // opaque string form once at the boundary. The @target-uri line must carry the
  // verbatim bytes the agent signed, never a WHATWG-normalized toString().
  const url = opaqueUrl(input.url);
  try {
    return buildSignatureBase(
      sig.covered,
      requestComponentValue({ method: input.method, url, header: (n) => input.headers.get(n) ?? undefined }),
      sig.rawInner,
    );
  } catch (err) {
    // ComponentUnavailable: a header or member the request does not carry. TypeError:
    // @authority covered on a URL that does not parse.
    if (err instanceof ComponentUnavailable || err instanceof TypeError) return undefined;
    throw err;
  }
}

type PresentedKey = { ok: true; key: Uint8Array<ArrayBuffer> } | { ok: false; result: PopResult };

function readPresentedKey(headers: Headers): PresentedKey {
  const raw = headers.get(AGENT_KEY_HEADER);
  if (!raw) return { ok: false, result: fail("missing_agent_key") };
  const bytes = decodeBase64Url(raw);
  if (!bytes || bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, result: fail("bad_agent_key") };
  }
  return { ok: true, key: bytes };
}

type ParsedProof = { ok: true; sig: ParsedSignature; count: number } | { ok: false; result: PopResult };

// parseProof reads the proof's Signature-Input and Signature through the structured-field
// parser. A request missing either header is unsigned, a refusal the fetcher fixes by
// signing; the first signature in header order is the proof.
function parseProof(headers: Headers): ParsedProof {
  const input = headers.get("signature-input") ?? undefined;
  const signature = headers.get("signature") ?? undefined;
  if (input === undefined || signature === undefined) return { ok: false, result: failAccept("missing_sig") };
  const parsed = parseSignatureHeaders(input, signature);
  if (!parsed.ok) return { ok: false, result: fail("malformed_sig_input") };
  return { ok: true, sig: parsed.value[0] as ParsedSignature, count: parsed.value.length };
}

// coversTheProfile reports whether the proof covers at least @method, @target-uri and a
// Signature-Agent reference. Anything else it covers is allowed and enters the base;
// which member the reference names, and whether it is the only one, is
// signatureDirectory's call.
function coversTheProfile(sig: ParsedSignature): boolean {
  const covers = (n: string, plainOnly: boolean): boolean =>
    sig.covered.some((c) => c.name.toLowerCase() === n && (!plainOnly || c.params.length === 0));
  return covers("@method", true) && covers("@target-uri", true) && covers("signature-agent", false);
}

// MAX_FUTURE_SKEW_SEC: a proof's created timestamp may not lead the verifier
// clock by more than this (mirrors the Go service-to-service verifier).
const MAX_FUTURE_SKEW_SEC = 300;

function freshnessFailure(sig: ParsedSignature, now?: () => number): PopFailure | undefined {
  const nowSec = Math.floor((now?.() ?? Date.now()) / 1000);
  if (sig.created === undefined) return "pop_missing_created";
  if (sig.created > nowSec + MAX_FUTURE_SKEW_SEC) return "pop_future_created";
  if (sig.expires === undefined) return "pop_missing_exp";
  if (nowSec >= sig.expires) return "pop_expired";
  return undefined;
}

const defaultVerifyEd25519: Ed25519Verify = async (pubkey, sig, message) => {
  try {
    const key = await crypto.subtle.importKey("raw", pubkey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, sig, message);
  } catch {
    return false;
  }
};
