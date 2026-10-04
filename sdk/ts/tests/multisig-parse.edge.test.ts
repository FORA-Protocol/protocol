// sdk/ts Signature-Input / Signature parse-edge units. The canonical Go golden vectors
// are well-behaved (no comma/paren inside a quoted keyid, no backslash escapes, canonical
// whitespace), so passing every vector does NOT gate the parser's correctness on an
// ADVERSARIAL header. Go delegates the dictionary parse to dunglas/httpsfv and only
// hand-rolls the verbatim-inner split (rawInnerByLabel / splitTopLevelMembers); the TS
// port parses with core/sfv.ts and keeps the same split, so these units pin the
// quoted-string / backslash-escape / top-level-comma behavior the RFC 8941 dictionary
// grammar requires.
//
// Faces under test:
//   core/multisig-parse.ts::splitTopLevelMembers — split one SFV dictionary header
//     value on TOP-LEVEL commas, honoring quoted strings + backslash escapes.
//   core/multisig-parse.ts::rawInnerByLabel — the VERBATIM member value after "label="
//     for each label, so each signature's base terminates with the signer's exact
//     @signature-params bytes.
//   core/multisig-parse.ts::parseSignatureHeaders — the structured parse of
//     Signature-Input and Signature; refuses (never mis-slices) a malformed header.

import { describe, it, expect } from "vitest";
import {
  splitTopLevelMembers,
  rawInnerByLabel,
  parseSignatureHeaders,
} from "../core/multisig-parse.ts";

describe("sdk/ts multi-member Signature-Input parse edges", () => {
  it("splits on top-level commas into one member per label", () => {
    const raw = 'sig1=("@method" "@target-uri"), sig2=("@method" "signature";key="sig1")';
    expect(splitTopLevelMembers(raw)).toEqual([
      'sig1=("@method" "@target-uri")',
      ' sig2=("@method" "signature";key="sig1")',
    ]);
  });

  it("does NOT split on a comma inside a quoted string (quoted keyid)", () => {
    // A keyid may legally contain a comma inside its quotes; a naive comma split
    // would tear the member in two and mis-slice both labels.
    const raw = 'sig1=("@method");keyid="agent,demo.v1", sig2=("@method");keyid="broker.relay.a"';
    const parts = splitTopLevelMembers(raw);
    expect(parts).toHaveLength(2);
    expect(parts[0]).toContain('keyid="agent,demo.v1"');
    expect(parts[1]).toContain('keyid="broker.relay.a"');
  });

  it("honors backslash escapes inside a quoted string", () => {
    // The escaped quote (\") must NOT close the string, so the following comma
    // stays inside quotes and does not split the member.
    const raw = 'sig1=("@method");keyid="a\\",b", sig2=("@method");keyid="c"';
    const parts = splitTopLevelMembers(raw);
    expect(parts).toHaveLength(2);
    expect(parts[0]).toContain('keyid="a\\",b"');
    expect(parts[1]).toContain('keyid="c"');
  });

  it("preserves the VERBATIM inner value per label", () => {
    // rawInnerByLabel returns everything after `label=` byte-for-byte — the
    // signer's exact @signature-params tail the verify base must terminate with.
    const raw =
      'sig1=("@method" "@target-uri");keyid="agent.v1";created=1700000000, sig2=("@method" "signature";key="sig1");keyid="broker.relay.a"';
    const inner = rawInnerByLabel([raw]);
    expect(inner["sig1"]).toBe(
      '("@method" "@target-uri");keyid="agent.v1";created=1700000000',
    );
    expect(inner["sig2"]).toBe(
      '("@method" "signature";key="sig1");keyid="broker.relay.a"',
    );
  });

  it("cleanly rejects a malformed header (missing close paren) rather than mis-slicing", () => {
    // An unterminated inner list must be REJECTED, not partially sliced into a bogus
    // covered set.
    const malformed = 'sig1=("@method" "@target-uri";keyid="agent.v1"';
    expect(parseSignatureHeaders(malformed, "sig1=:AAAA:")).toEqual({ ok: false, refusal: { kind: "malformed" } });
  });

  it("parses a quoted comma and an escaped quote inside a keyid into the right labels", () => {
    const input = 'sig1=("@method");created=1;keyid="a\\",b", sig2=("@method";key="x");keyid="c,d"';
    const parsed = parseSignatureHeaders(input, "sig1=:AAAA:, sig2=:AAAA:");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.map((p) => [p.label, p.keyid])).toEqual([
      ["sig1", 'a",b'],
      ["sig2", "c,d"],
    ]);
    expect(parsed.value[1]?.covered).toEqual([{ name: "@method", params: [{ key: "key", value: "x" }] }]);
    expect(parsed.value[0]?.rawInner).toBe('("@method");created=1;keyid="a\\",b"');
  });

  it("carries a Boolean component flag such as \"@authority\";req", () => {
    const parsed = parseSignatureHeaders('sig1=("@authority";req "content-digest");keyid="k"', "sig1=:AAAA:");
    expect(parsed.ok && parsed.value[0]?.covered[0]).toEqual({ name: "@authority", params: [{ key: "req", value: true }] });
  });

  it("refuses a member with no keyid, a parameter of the wrong type, or a label missing from Signature", () => {
    for (const [input, sig] of [
      ['sig1=("@method");created=1', "sig1=:AAAA:"],
      ['sig1=("@method");keyid="k";created="1"', "sig1=:AAAA:"],
      ['sig1=("@method");keyid=k', "sig1=:AAAA:"],
      ['sig1=("@method");keyid="k"', "sig2=:AAAA:"],
      ['sig1=("@method");keyid="k"', 'sig1="AAAA"'],
      ['sig1="not-a-list";keyid="k"', "sig1=:AAAA:"],
    ]) {
      expect(parseSignatureHeaders(input, sig), input).toEqual({ ok: false, refusal: { kind: "malformed" } });
    }
  });

  it("answers a request missing either header as unsigned, distinct from malformed", () => {
    expect(parseSignatureHeaders(undefined, "sig1=:AAAA:")).toEqual({ ok: false, refusal: { kind: "unsigned" } });
    expect(parseSignatureHeaders('sig1=("@method");keyid="k"', undefined)).toEqual({
      ok: false,
      refusal: { kind: "unsigned" },
    });
  });
});
