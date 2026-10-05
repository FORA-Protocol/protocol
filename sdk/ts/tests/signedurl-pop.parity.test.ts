// Signed-URL + Web Bot Auth delivery-proof byte-parity (TypeScript side).
//
// The Core Invariant for these two helpers is byte-identical output to the
// sdk/go oracle. Per the user-decided parity contract ("Go golden-emitter ->
// shared testdata"), the implement step adds a Go golden
// emitter under sdk/go/helpers that signs with the REAL Go signer and writes:
//
//   sdk/go/helpers/testdata/signedurl-vectors.json  (SignURLEd25519 output)
//   sdk/go/helpers/testdata/pop-vectors.json        (Web Bot Auth delivery-proof output)
//
// This test asserts sdk/ts verify reaches the recorded verdict for each vector. The
// pop vectors' verdicts, refusal tokens and Accept-Signature values come from the Go
// verifier (helpers.VerifyAgentBinding), and all three are replayed.
//
// LOAD-BEARING (why vectors come from the Go signer, never hand-authored):
// SignURLEd25519 emits the URL with a SORTED query (url.Values.Encode()); the
// TS verifier does NOT re-sort — it only strips `sig` and verifies "GET\n<url>".
// They agree ONLY when the verifier is fed the Go signer's canonically-sorted
// output. Hand-authored vectors would silently defeat that guard.
//
// PoP portability: pop.ts must expose the Ed25519 verify primitive as an
// INJECTABLE dependency (Fastly Compute lacks Ed25519 in SubtleCrypto). We drive
// BOTH a default-WebCrypto-primitive case (byte-identical output observed on the
// default path, not merely asserted in prose) AND an injected-primitive case.
import { describe, it, expect } from "vitest";
import { verifyEd25519SignedUrl } from "../src/verify.ts";
import { POP_ACCEPT_SIGNATURE, verifyAgentBinding } from "../src/pop.ts";
import { signInbound } from "../core/sign.ts";
import { importSigningKey } from "./wba-fixtures.ts";
// The vector files are produced by the Go golden emitter (helpers/gen_vectors_test.go).
import signedUrlVectors from "../../go/helpers/testdata/signedurl-vectors.json";
import popVectors from "../../go/helpers/testdata/pop-vectors.json";

// ---- signed-URL vectors ----------------------------------------------------
// Each vector is produced by SignURLEd25519 signing an unsigned URL; the TS
// verify (fed the injected resolveKey that returns the vector's public key) must
// reach the recorded verdict.
type SignedUrlVector = {
  name: string;
  pub_b64url: string; // raw 32-byte Ed25519 public key
  kid: string;
  signed_url: string; // SignURLEd25519 output (canonically-sorted query, incl. sig)
  now_unix: number; // clock the verifier is pinned to
  expected_valid: boolean;
};

// ---- PoP vectors -----------------------------------------------------------
// Each vector carries the full delivery-proof material the Go signer emitted: the
// presented raw public key, the request line, the Signature-Agent / Signature-Input /
// Signature headers, the URL-bound agent_id (== thumbprint of presented key), and the
// clock. TS verifyAgentBinding must reach the recorded verdict.
type PopVector = {
  name: string;
  method: string;
  url: string; // @target-uri (carries agent_id param)
  agent_id: string; // thumbprint of the presented key
  presented_key_b64url: string; // raw 32-byte Ed25519 public key
  signer_seed_hex: string;
  agent_directory: string; // the directory origin the signer was given
  nonce?: string;
  signature_agent: string; // Signature-Agent header value; "" means absent
  signature_input: string; // RFC 9421 Signature-Input header value
  signature: string; // RFC 9421 Signature header value
  now_unix: number;
  expected_valid: boolean;
  expected_reason: string; // the Go verifier's refusal token; "" when valid
  expected_accept_signature?: string; // set when the refusal is answered with one
};

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importEd25519PublicKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, [
    "verify",
  ]);
}

describe("sdk/ts signed-URL verify matches the Go signer vectors", () => {
  const vectors = signedUrlVectors as SignedUrlVector[];

  it("vector file is non-empty", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const v of vectors) {
    it(`${v.name} -> valid=${v.expected_valid}`, async () => {
      const pub = await importEd25519PublicKey(b64urlToBytes(v.pub_b64url));
      const res = await verifyEd25519SignedUrl(v.signed_url, {
        now: () => v.now_unix * 1000,
        resolveKey: async (kid: string | undefined) =>
          kid === v.kid ? pub : undefined,
      });
      expect(res.valid).toBe(v.expected_valid);
    });
  }
});

describe("sdk/ts Web Bot Auth delivery-proof verify matches the Go signer vectors", () => {
  const vectors = popVectors as PopVector[];

  it("vector file is non-empty", () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  it("every vector records its refusal token, and some refusals an Accept-Signature", () => {
    for (const v of vectors) {
      expect(typeof v.expected_reason, v.name).toBe("string");
      expect(v.expected_valid, v.name).toBe(v.expected_reason === "");
    }
    expect(vectors.filter((v) => v.expected_accept_signature !== undefined).length).toBeGreaterThan(0);
  });

  // headersFor writes a vector's request headers: the presented key and, when the
  // vector carries them, the three signature headers ("" means absent).
  function headersFor(v: PopVector): Headers {
    const h = new Headers();
    h.set("x-fora-agent-key", v.presented_key_b64url);
    if (v.signature_input !== "") h.set("signature-input", v.signature_input);
    if (v.signature !== "") h.set("signature", v.signature);
    if (v.signature_agent !== "") h.set("signature-agent", v.signature_agent);
    return h;
  }

  // The vector's whole verdict: validity, the refusal token and the Accept-Signature.
  function expectVerdict(v: PopVector, res: Awaited<ReturnType<typeof verifyAgentBinding>>): void {
    expect(res.ok).toBe(v.expected_valid);
    expect(res.reason ?? "").toBe(v.expected_reason);
    expect(res.acceptSignature).toBe(v.expected_accept_signature);
  }

  // DEFAULT-primitive path: verifyAgentBinding uses its built-in WebCrypto
  // Ed25519 verify. This observes byte-identical output on the default path.
  for (const v of vectors) {
    it(`[default primitive] ${v.name} -> ok=${v.expected_valid}`, async () => {
      const res = await verifyAgentBinding({
        method: v.method,
        url: v.url,
        headers: headersFor(v),
        agentId: v.agent_id,
        now: () => v.now_unix * 1000,
      });
      expectVerdict(v, res);
      if (v.expected_valid) expect(res.signatureAgent).toBe(v.agent_directory);
      if (v.expected_accept_signature !== undefined) expect(res.acceptSignature).toBe(POP_ACCEPT_SIGNATURE);
    });
  }

  // RE-SIGN: signInbound, given the vector's seed, directory, nonce and window,
  // reproduces the Go signer's Signature-Agent, Signature-Input and Signature byte for
  // byte. Only the vectors Go produced through SignAgentBinding unaltered qualify.
  for (const v of vectors.filter((x) => ["valid", "valid_no_nonce", "expired"].includes(x.name))) {
    it(`[re-sign] ${v.name}: signInbound reproduces the Go proof`, async () => {
      const created = Number(/;created=(\d+)/.exec(v.signature_input)?.[1]);
      const expires = Number(/;expires=(\d+)/.exec(v.signature_input)?.[1]);
      const keyPair = {
        privateKey: await importSigningKey(v.signer_seed_hex),
        publicKey: await crypto.subtle.importKey("raw", b64urlToBytes(v.presented_key_b64url), { name: "Ed25519" }, true, [
          "verify",
        ]),
      };
      const req = await signInbound(keyPair, v.url, {
        signatureAgent: v.agent_directory,
        ...(v.nonce !== undefined ? { nonce: v.nonce } : {}),
        window: () => [created, expires],
      });
      expect(req.headers.get("signature-agent")).toBe(v.signature_agent);
      expect(req.headers.get("signature-input")).toBe(v.signature_input);
      expect(req.headers.get("signature")).toBe(v.signature);
      expect(req.headers.get("x-fora-agent-key")).toBe(v.presented_key_b64url);
    });
  }

  it("[re-sign] member_not_https_origin: signInbound refuses a directory that is not an https origin", async () => {
    const v = vectors.find((x) => x.name === "member_not_https_origin") as PopVector;
    const keyPair = {
      privateKey: await importSigningKey(v.signer_seed_hex),
      publicKey: await crypto.subtle.importKey("raw", b64urlToBytes(v.presented_key_b64url), { name: "Ed25519" }, true, [
        "verify",
      ]),
    };
    await expect(signInbound(keyPair, v.url, { signatureAgent: v.agent_directory })).rejects.toMatchObject({
      reason: "signature_agent_not_origin",
    });
  });

  // INJECTED-primitive path: the same vectors verified through a caller-supplied
  // Ed25519 verify primitive (the Fastly-style non-WebCrypto path). The verdict
  // MUST match the default path — the byte contract is the signature base, not
  // the primitive.
  for (const v of vectors) {
    it(`[injected primitive] ${v.name} -> ok=${v.expected_valid}`, async () => {
      const injectedVerify = async (
        pub: Uint8Array<ArrayBuffer>,
        sig: Uint8Array<ArrayBuffer>,
        msg: Uint8Array<ArrayBuffer>,
      ): Promise<boolean> => {
        const key = await importEd25519PublicKey(pub);
        return crypto.subtle.verify("Ed25519", key, sig, msg);
      };
      const res = await verifyAgentBinding({
        method: v.method,
        url: v.url,
        headers: headersFor(v),
        agentId: v.agent_id,
        now: () => v.now_unix * 1000,
        verifyEd25519: injectedVerify,
      });
      expectVerdict(v, res);
    });
  }
});
