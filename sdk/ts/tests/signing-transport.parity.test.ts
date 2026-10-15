// sdk/ts SigningTransport / signOutbound outbound auto-sign parity + behavior.
//
// The TS sibling of Go core.NewSigningTransport + SigningOption and Python
// SigningTransport / SignedOutbound:
//   - signOutbound({ privKey, keyid, method, url, body, authorization,
//     signatureAgent, window, appendOnly, coverPrevious, prior? }) -> { headers, body }
//     (transport-neutral header core, Python SignedOutbound sibling);
//   - createSigningTransport(send, opts) -> a WHATWG-fetch-shaped send that buffers
//     the body, stamps the RFC 9421 headers via signOutbound, and forwards the SAME
//     body bytes to the wrapped send.
//
// Core Invariant (agentic-content-access): the transport is a pure ORCHESTRATION of
// the already-parity-locked signRequest / appendSignature + clockWindow
// primitives — it stamps RFC 9421 headers byte-identical to the
// shared Go/Python oracle, forwards the request body UNMODIFIED, and adds NO new
// crypto and NO new signature-base rendering.
//
// Proof strategy (corpus-first, no new emitter): replay the SAME shared Go vectors
// the primitive suites already verify against
// (sdk/go/helpers/testdata/sign-request-vectors.json for the fresh-sig and
// append paths, multisig-chain-vectors.json for a second signer) THROUGH the
// transport via a capturing fake send, and assert the stamped headers equal the
// vector fields byte-for-byte. Each vector injects a FIXED window
// ()=>[v.created, v.expires] — the DEFAULT clockWindow(now) drifts created/expires
// and the base would not reproduce; the windowless sign-request.parity.test.ts
// harness is adapted, NOT copied verbatim.

import { describe, it, expect } from "vitest";
import { createSigningTransport, type SignerSource, signOutbound } from "../core/signing-transport.ts";
// The append path reuses the already-landed primitives to arrange the upstream sig1
// state the second signer's transport appends to.
import { signRequest } from "../core/sign-request.ts";
import { WebBotAuthError } from "../core/wba.ts";
// Use the EXPORTED header constant (do NOT string-literal "signature-agent").
import { SignatureAgentHeader } from "../src/wire.ts";
// The signer EMITS the lowercase spelling, so a merge over a caller's own headers
// replaces rather than duplicates — two field lines under one covered name break the
// rebuilt signature base. Derived from the exported constant, never string-literalled.
const SignatureAgentEmitted = SignatureAgentHeader.toLowerCase();
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
import multisigVectors from "../../go/helpers/testdata/multisig-chain-vectors.json";

// ---------------------------------------------------------------------------
// Vector shapes (shared Go emitter output — the sole oracle).
// ---------------------------------------------------------------------------

type SignRequestVector = {
  name: string;
  method: string;
  url: string;
  body_hex: string;
  authorization: string;
  /** The key-directory ORIGIN the signer was given. */
  signature_agent: string;
  append_only?: boolean;
  keyid: string;
  created: number;
  expires: number;
  /** RFC 9421 nonce the oracle signed with; absent when it signed without one. */
  nonce?: string;
  signer_seed_hex: string;
  content_digest: string;
  signature_input: string;
  signature: string;
  /** What the SIGNER puts on a bare request — what is SENT, as against every other
   * field here, which records what was SIGNED. A LIST per name because that is what
   * the verifier reads: it joins repeated values with ", " before rebuilding the base. */
  emitted_headers: Record<string, string[]>;
};

/** This face returns one value per name and cannot hold a duplicate, so each wraps to a
 * one-element list. The keys are compared VERBATIM: normalizing the casing here is what
 * previously hid a signed key spelled differently from the one a caller supplies, which
 * puts two field lines on the wire and breaks the rebuilt base. */
function asEmitted(h: Record<string, string>): Record<string, string[]> {
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k, [v]]));
}

type MultisigHop = {
  keyid: string;
  pubkey_b64url: string;
  seed_hex: string;
  directory: string;
  nonce?: string;
  cover_previous?: boolean;
};
type MultisigChainVector = {
  name: string;
  method: string;
  url: string;
  body_hex: string;
  authorization: string;
  signature_agent: string;
  created: number;
  expires: number;
  content_digest: string;
  signature_input: string;
  signature: string;
  hops: MultisigHop[];
};

// ---------------------------------------------------------------------------
// Byte helpers (adapted from sign-request.parity.test.ts — but the transport
// replay injects a FIXED window, it is NOT the windowless direct-signRequest
// harness).
// ---------------------------------------------------------------------------

const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function utf8(s: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(new TextEncoder().encode(s)) as Uint8Array<ArrayBuffer>;
}

async function importSigningKey(seedHex: string): Promise<CryptoKey> {
  const seed = hexToBytes(seedHex);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
    "sign",
  ]);
}

// The key-directory origin the option-behavior transports sign as.
const TEST_DIR = "https://agent.example.com";

// A freshly generated signer for the option-behavior legs, which pin plumbing
// (window/append/predicate/directory), NOT byte-parity — any real key works.
async function genSigner(): Promise<{ privKey: CryptoKey; keyid: string; signatureAgent: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { privKey: kp.privateKey, keyid: "test-key.v1", signatureAgent: TEST_DIR };
}

function bytesEqual(
  a: Uint8Array | undefined,
  b: Uint8Array | undefined,
): boolean {
  if (a === undefined || b === undefined) return a === b;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// The WHATWG-fetch-shaped outbound seam the transport wraps: send(url, init)
// carrying method/headers/body. The capturing fake records every forwarded call
// so a test can inspect the stamped headers AND the forwarded body bytes.
type Init = {
  method?: string;
  headers?: Record<string, string>;
  body?: Uint8Array<ArrayBuffer>;
};
type Captured = { url: string; init: Init };

function capturingSend(): {
  send: (url: string, init: Init) => Promise<{ status: number }>;
  calls: Captured[];
} {
  const calls: Captured[] = [];
  const send = async (url: string, init: Init) => {
    calls.push({ url, init });
    return { status: 200 };
  };
  return { send, calls };
}

// ---------------------------------------------------------------------------
// (a)+(b) PARITY + BODY-INTEGRITY through the transport.
// ---------------------------------------------------------------------------

describe("createSigningTransport replays the shared Go sign-request vectors byte-identically", () => {
  const doc = signRequestVectors as { vectors: SignRequestVector[] };

  it("vector matrix is non-empty and every vector names a directory origin", () => {
    expect(doc.vectors.length).toBeGreaterThan(0);
    for (const v of doc.vectors) expect(v.signature_agent).toMatch(/^https:\/\//);
  });

  // The transport refuses to sign without a nonce, so it replays only the
  // vectors signed with one; the signRequest parity tests replay every vector.
  for (const v of doc.vectors.filter((x) => x.nonce !== undefined)) {
    it(`${v.name}: transport stamps Content-Digest/Signature-Input/Signature === Go oracle AND forwards the body unmodified`, async () => {
      const { send, calls } = capturingSend();
      const priv = await importSigningKey(v.signer_seed_hex);

      // FIXED window per vector: reproduce the vector's created/expires;
      // the default clockWindow(now) would drift the base.
      const signing = createSigningTransport(send, {
        privKey: priv,
        keyid: v.keyid,
        window: () => [v.created, v.expires] as [number, number],
        // The transport mints a random nonce per signature; pin it to the vector's.
        nonce: () => v.nonce ?? "",
        signatureAgent: v.signature_agent,
        appendOnly: v.append_only ?? false,
      });

      const body = hexToBytes(v.body_hex);
      await signing(v.url, {
        method: v.method,
        // Spelled the CONVENTIONAL HTTP way, deliberately differing in case from the
        // lowercase key the signer emits. Every test here used to pass the one spelling
        // that cannot collide, which is why a signed key landing BESIDE a caller's rather
        // than replacing it went unseen through a whole green suite.
        headers: { Authorization: v.authorization },
        body,
      });

      expect(calls.length).toBe(1);
      const fwd = calls[0] as Captured;
      const h = fwd.init.headers ?? {};

      // (a) PARITY: the stamped RFC 9421 artifacts equal the Go oracle fields.
      expect(h["content-digest"]).toBe(v.content_digest);
      expect(h["signature-input"]).toBe(v.signature_input);
      expect(h.signature).toBe(v.signature);

      // (c) ONE FIELD LINE PER COVERED NAME. Header names are case-insensitive on the
      // wire and JS object keys are not, so a caller's spelling surviving beside the
      // signed one puts the name on the wire twice; the verifier joins repeated values
      // with ", " before rebuilding the base, and a correct signature is then refused.
      // Asserted over the WHOLE forwarded map — the emitted set is what the corpus
      // records, and the caller's differently-cased key must be gone from it.
      const names = Object.keys(h).map((k) => k.toLowerCase());
      expect(new Set(names).size, `duplicated header names: ${names}`).toBe(names.length);
      expect(asEmitted(h)).toEqual(v.emitted_headers);

      // (b) BODY-INTEGRITY (the key regression guard): the FORWARDED body bytes
      // must equal the input body. A wrapper that buffers-for-digest but forwards
      // a consumed/empty body would still stamp a correct header and ship green —
      // so assert the body itself, not only the header.
      expect(bytesEqual(fwd.init.body, body)).toBe(true);
      // Recompute the digest over the FORWARDED body to double-lock (b): a body
      // swap that preserved length would still be caught here.
      const fwdDigest = new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          fwd.init.body ?? new Uint8Array(),
        ),
      );
      let b64 = "";
      // eslint-disable-next-line no-undef
      b64 = btoa(String.fromCharCode(...fwdDigest));
      expect(h["content-digest"]).toBe(`sha-256=:${b64}:`);
    });
  }
});

// ---------------------------------------------------------------------------
// signOutbound — the transport-neutral header core (Python SignedOutbound
// sibling). Same vectors, asserted directly on the returned {headers, body}.
// ---------------------------------------------------------------------------

describe("signOutbound returns the RFC 9421 header set byte-identical to the Go oracle", () => {
  const doc = signRequestVectors as { vectors: SignRequestVector[] };

  // The transport refuses to sign without a nonce, so it replays only the
  // vectors signed with one; the signRequest parity tests replay every vector.
  for (const v of doc.vectors.filter((x) => x.nonce !== undefined)) {
    it(`${v.name}: header core matches the oracle and returns the body unchanged`, async () => {
      const priv = await importSigningKey(v.signer_seed_hex);
      const body = hexToBytes(v.body_hex);
      const out = await signOutbound({
        privKey: priv,
        keyid: v.keyid,
        method: v.method,
        url: v.url,
        body,
        authorization: v.authorization,
        signatureAgent: v.signature_agent,
        window: () => [v.created, v.expires] as [number, number],
        nonce: () => v.nonce ?? "",
        appendOnly: v.append_only ?? false,
      });

      expect(out.headers["content-digest"]).toBe(v.content_digest);
      expect(out.headers["signature-input"]).toBe(v.signature_input);
      expect(out.headers.signature).toBe(v.signature);

      // The WHOLE emitted set, compared as a map rather than key by key.
      //
      // Every assertion above says what was SIGNED; emitted_headers says what is
      // SENT, and the two are different claims. A verifier rebuilds the base from
      // the request it received, so a covered value bound but never sent is not
      // bound: it reads the covered names off signature-input, finds nothing under
      // one of them, and refuses. A port that bound authorization and signature-agent
      // and attached neither matched the oracle byte-for-byte on all three fields above
      // and could not complete a single signed call.
      //
      // Membership assertions are what let that ship. A map comparison is what
      // notices the next header to go missing.
      expect(asEmitted(out.headers)).toEqual(v.emitted_headers);

      // Transport-neutral core forwards the body untouched.
      expect(bytesEqual(out.body, body)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// (c) APPEND path — a second signer adds its own member beside the agent's, which
// stays byte-for-byte untouched, and reproduces the Go two-signature vectors.
// ---------------------------------------------------------------------------

describe("createSigningTransport append path mirrors the Go multi-signature vectors", () => {
  const doc = multisigVectors as { vectors: MultisigChainVector[] };
  const byName = (n: string): MultisigChainVector => {
    const v = doc.vectors.find((x) => x.name === n);
    if (!v) throw new Error(`missing vector ${n}`);
    return v;
  };

  // The transport refuses to sign without a nonce, so only the vector whose hops were
  // signed with one is replayed through it.
  for (const name of ["positive_covering_two_nonce"]) {
    it(`${name}: the second signer's appendOnly transport reproduces the Go headers`, async () => {
      const v = byName(name);
      const h1 = v.hops[0] as MultisigHop;
      const h2 = v.hops[1] as MultisigHop;
      const body = hexToBytes(v.body_hex);

      // Arrange the incoming request state: the agent's sig1 and its member.
      const sig1 = await signRequest(await importSigningKey(h1.seed_hex), {
        method: v.method,
        url: v.url,
        body,
        authorization: v.authorization,
        signatureAgent: h1.directory,
        keyid: h1.keyid,
        created: v.created,
        expires: v.expires,
        nonce: h1.nonce ?? "",
      });

      const { send, calls } = capturingSend();
      const signing = createSigningTransport(send, {
        privKey: await importSigningKey(h2.seed_hex),
        keyid: h2.keyid,
        window: () => [v.created, v.expires] as [number, number],
        nonce: () => h2.nonce ?? "",
        appendOnly: true,
        coverPrevious: h2.cover_previous ?? false,
        signatureAgent: h2.directory,
      });

      await signing(v.url, {
        method: v.method,
        headers: {
          authorization: v.authorization,
          [SignatureAgentHeader]: sig1.signatureAgent,
          "content-digest": sig1.contentDigest,
          "signature-input": sig1.signatureInput,
          signature: sig1.signature,
        },
        body,
      });

      expect(calls.length).toBe(1);
      const fwd = calls[0] as Captured;
      const h = fwd.init.headers ?? {};
      // The agent's member is untouched and the second signer's is appended beside it.
      expect(h[SignatureAgentEmitted]).toBe(v.signature_agent);
      expect(h["signature-input"]).toBe(v.signature_input);
      expect(h.signature).toBe(v.signature);
      expect(bytesEqual(fwd.init.body, body)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// (d) OPTION-behavior — ported from sdk/go/core/transport_options_test.go.
// These pin the transport's plumbing (window / append / predicate / directory /
// signer source / defaults / no-body), not byte-parity, so a freshly generated signer
// is used.
// ---------------------------------------------------------------------------

describe("createSigningTransport option behavior (ported from Go transport_options_test.go)", () => {
  const BODY = utf8('{"test":true}');

  it("WithWindow: injects the supplied created/expires into Signature-Input", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      ...(await genSigner()),
      window: () => [1_700_000_000, 1_700_000_300] as [number, number],
    });

    await signing(
      "https://exchange.example.com/fora.exchange.v1.ExchangeService/DiscoverResources",
      { method: "POST", headers: {}, body: BODY },
    );

    const sigInput = (calls[0] as Captured).init.headers?.["signature-input"];
    expect(sigInput).toBeDefined();
    expect(sigInput).toContain("created=1700000000");
    expect(sigInput).toContain("expires=1700000300");
  });

  it("appendOnly on a FRESH request still produces a valid sig1", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, { ...(await genSigner()), appendOnly: true });

    await signing("https://exchange.example.com/fora.x/Y", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const sigInput = (calls[0] as Captured).init.headers?.["signature-input"] ?? "";
    expect(sigInput).toContain("sig1=");
    expect(sigInput).not.toContain("sig2=");
  });

  it("a request already carrying a Signature gets a second signature (sig2), never a replacement", async () => {
    // Prior-detection branch (Go sign(): appendOnly || req has Signature) — even
    // WITHOUT appendOnly, an incoming Signature selects the append path.
    const upstream = await genSigner();
    const sig1 = await signRequest(upstream.privKey, {
      method: "POST",
      url: "https://exchange.example.com/fora.x/Y",
      body: BODY,
      authorization: "",
      signatureAgent: upstream.signatureAgent,
      keyid: upstream.keyid,
      created: 1_700_000_000,
      expires: 1_700_000_300,
    });

    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      ...(await genSigner()),
      signatureAgent: "https://broker.example.com",
    }); // no appendOnly

    await signing("https://exchange.example.com/fora.x/Y", {
      method: "POST",
      headers: {
        "content-digest": sig1.contentDigest,
        [SignatureAgentHeader]: sig1.signatureAgent,
        "signature-input": sig1.signatureInput,
        signature: sig1.signature,
      },
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toContain("sig1=");
    expect(h["signature-input"]).toContain("sig2=");
    expect(h.signature).toContain("sig1=");
    expect(h.signature).toContain("sig2=");
    expect(h[SignatureAgentEmitted]).toBe(`sig1="${TEST_DIR}", sig2="https://broker.example.com"`);
    // Without coverPrevious the second signature covers only its own request and member.
    expect(h["signature-input"]?.split("sig2=")[1]).not.toContain('"signature";key=');
  });

  it("signatureAgent: the directory becomes the signature's own covered member", async () => {
    const dir = "https://broker.example.com";
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, { ...(await genSigner()), signatureAgent: dir });

    await signing("https://exchange.example.com/fora.x/Y", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h[SignatureAgentEmitted]).toBe(`sig1="${dir}"`);
    expect(h["signature-input"]).toContain('"signature-agent";key="sig1"');
    expect(h["signature-input"]).toContain('tag="web-bot-auth"');
  });

  it("signatureAgent: an incoming Signature-Agent with no signature is replaced, not kept", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, await genSigner());

    await signing("https://exchange.example.com/fora.x/Y", {
      method: "POST",
      headers: { [SignatureAgentHeader]: 'sig1="https://other.example"' },
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h[SignatureAgentEmitted]).toBe(`sig1="${TEST_DIR}"`);
    expect(Object.keys(h).filter((k) => k.toLowerCase() === "signature-agent")).toHaveLength(1);
  });

  it("refuses to sign without a directory, or with one that is not an https origin, and sends nothing", async () => {
    const { privKey, keyid } = await genSigner();
    for (const signatureAgent of [undefined, "http://agent.example.com", "https://agent.example.com/keys"]) {
      const { send, calls } = capturingSend();
      const signing = createSigningTransport(send, {
        privKey,
        keyid,
        ...(signatureAgent !== undefined ? { signatureAgent } : {}),
      });
      const err = await signing("https://exchange.example.com/fora.x/Y", { method: "POST", headers: {}, body: BODY }).catch(
        (e: unknown) => e,
      );
      expect(err, String(signatureAgent)).toBeInstanceOf(WebBotAuthError);
      expect(calls).toHaveLength(0);
    }
  });

  it("refuses a window longer than MAX_SIGNATURE_LIFETIME and sends nothing", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      ...(await genSigner()),
      window: () => [1_700_000_000, 1_700_000_600] as [number, number],
    });
    await expect(
      signing("https://exchange.example.com/fora.x/Y", { method: "POST", headers: {}, body: BODY }),
    ).rejects.toMatchObject({ reason: "signature_lifetime" });
    expect(calls).toHaveLength(0);
  });

  it("each signature carries a fresh 64-byte nonce", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, await genSigner());
    await signing("https://exchange.example.com/fora.x/Y", { method: "POST", headers: {}, body: BODY });
    const input = (calls[0] as Captured).init.headers?.["signature-input"] ?? "";
    const nonce = /;nonce="([^"]*)"/.exec(input)?.[1] ?? "";
    expect(nonce).toHaveLength(86);
    const bin = atob(nonce.replace(/-/g, "+").replace(/_/g, "/") + "==");
    expect(bin.length).toBe(64);
  });

  it("signerSource: signs as the source's identity, distinct signatures for identical requests in one second", async () => {
    const { privKey, keyid } = await genSigner();
    const source: SignerSource = (req) => ({
      privKey,
      keyid,
      signatureAgent: `https://${req.headers["x-tenant"]}.agents.example`,
    });
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      signerSource: source,
      window: () => [1_700_000_000, 1_700_000_060] as [number, number],
    });
    for (let i = 0; i < 2; i += 1) {
      await signing("https://exchange.example.com/fora.x/Y", {
        method: "POST",
        headers: { "x-tenant": "alice" },
        body: BODY,
      });
    }
    const [a, b] = calls.map((c) => c.init.headers ?? {});
    expect(a?.[SignatureAgentEmitted]).toBe('sig1="https://alice.agents.example"');
    expect(a?.["signature-input"]).toContain(`keyid="${keyid}"`);
    expect(a?.signature).not.toBe(b?.signature);
  });

  it("signerSource: an error or no signer sends nothing", async () => {
    const sources: SignerSource[] = [
      () => {
        throw new Error("no identity for this caller");
      },
      () => undefined,
    ];
    for (const signerSource of sources) {
      const { send, calls } = capturingSend();
      const signing = createSigningTransport(send, { signerSource });
      await expect(
        signing("https://exchange.example.com/fora.x/Y", { method: "POST", headers: {}, body: BODY }),
      ).rejects.toThrow();
      expect(calls).toHaveLength(0);
    }
  });

  it("coverPrevious: an appended signature covers the earlier one completely", async () => {
    const agent = await genSigner();
    const first = capturingSend();
    await createSigningTransport(first.send, agent)("https://exchange.example.com/fora.x/Y", {
      method: "POST",
      headers: {},
      body: BODY,
    });
    const signedHeaders = (first.calls[0] as Captured).init.headers ?? {};

    const { send, calls } = capturingSend();
    const forwarder = createSigningTransport(send, {
      ...(await genSigner()),
      signatureAgent: "https://relay.example.com",
      appendOnly: true,
      coverPrevious: true,
    });
    await forwarder("https://exchange.example.com/fora.x/Y", { method: "POST", headers: signedHeaders, body: BODY });

    const sig2 = (calls[0] as Captured).init.headers?.["signature-input"]?.split("sig2=")[1] ?? "";
    for (const want of ['"signature";key="sig1"', '"signature-input";key="sig1"', '"signature-agent";key="sig1"']) {
      expect(sig2).toContain(want);
    }
  });

  it("predicate returning FALSE: request passes through UNSIGNED (not an error)", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      ...(await genSigner()),
      predicate: () => false,
    });

    await signing(
      "https://exchange.example.com/fora.exchange.v1.ExchangeService/DiscoverResources",
      { method: "POST", headers: {}, body: BODY },
    );

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeUndefined();
    // Pass-through still forwards the body untouched.
    expect(bytesEqual((calls[0] as Captured).init.body, BODY)).toBe(true);
  });

  it("predicate returning TRUE: signs even a non-/fora path", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, {
      ...(await genSigner()),
      predicate: () => true,
    });

    await signing("https://exchange.example.com/other.service/Method", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeDefined();
  });

  it("default (only the identity): signs any bodied request", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, await genSigner());

    await signing("https://exchange.example.com/fora.x/Y", {
      method: "POST",
      headers: {},
      body: BODY,
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeDefined();
    expect(h["content-digest"]).toBeDefined();
  });

  it("no-body request: passes through UNSIGNED (nothing to bind Content-Digest to)", async () => {
    const { send, calls } = capturingSend();
    const signing = createSigningTransport(send, await genSigner());

    await signing("https://exchange.example.com/fora.x/Y", {
      method: "GET",
      headers: {},
    });

    const h = (calls[0] as Captured).init.headers ?? {};
    expect(h["signature-input"]).toBeUndefined();
    expect(h["content-digest"]).toBeUndefined();
    expect((calls[0] as Captured).init.body).toBeUndefined();
  });
});
