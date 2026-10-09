# Published JSON Schemas

Generated from [`proto/`](../../proto). **Do not edit the `.json` files by hand.**
Regenerate with `scripts/gen-sdk-types.sh` and commit the result; CI regenerates them
and fails on any difference.

One JSON Schema (draft 2020-12) per message of the wire contract (`fora.v1` and
`fora.admin.v1`), named by the fully-qualified message name, in two variants:

| File | Unknown fields |
|---|---|
| `fora.v1.ResourceResponse.schema.json` | accepted, as the generated SDK models accept them |
| `fora.v1.ResourceResponse.schema.strict.json` | refused: `additionalProperties: false` on every message object, at every depth |

A conformance check uses the strict variant, so an unknown or misspelled field fails the
check. The default variant suits a reader that must accept messages from a newer
protocol version.

Each file is self-contained: the message is the document root, and every message it
references is inlined under `$defs`, keyed by its fully-qualified name. Validate against
one file with any draft 2020-12 validator; no schema registry and no network access are
needed.

## Where to get them

| Package | Access |
|---|---|
| Go module `github.com/FORA-Protocol/protocol` | this directory; `jsonschema.Load("fora.v1.ResourceResponse", true)` or `jsonschema.FS` from package `github.com/FORA-Protocol/protocol/gen/jsonschema` |
| `fora-protocol` on PyPI | `wire.schemas.load("fora.v1.ResourceResponse", strict=True)`; `wire.schemas.names()` lists the messages |
| `@fora-protocol/sdk` on npm | export path `@fora-protocol/sdk/jsonschema/fora.v1.ResourceResponse.schema.strict.json` |

## What the schemas encode

The schemas come from the same pinned generator the SDK models are built from,
`bufbuild/protoschema-plugins` `protoc-gen-jsonschema` v0.6.0, reshaped by
`scripts/sdk-types/gen_jsonschema.py` to describe canonical proto-JSON as the FORA wire
carries it. The two variants differ only in the unknown-field policy. Every decision
below applies to both.

- **Field names are the proto field names (snake_case).** That is the FORA wire naming:
  servers render proto-JSON with the proto names, the SDKs send them, and the canonical
  signing form uses them. The generator also emits the lowerCamel JSON names as aliases;
  they are removed, so a camelCase key is an unknown field. The strict variant refuses
  it.
- **`google.protobuf.Struct` stays open.** Every `ext` field is a Struct: a plain JSON
  object whose keys the contract does not define. The strict variant closes the message
  objects of the contract and never reaches inside a Struct, at any depth.
  `google.protobuf.Value` is any JSON value. Map fields keep their value schema as
  `additionalProperties`.
- **64-bit integers accept a decimal string or a JSON integer.** Canonical proto-JSON,
  and so a FORA server, emits an `int64` as a string (`"limit": "5"`); the SDKs send a
  JSON number. A bound applies to both forms: `Quota.limit` (`gte: 1`) refuses `0` and
  `"0"`.
- **Other numbers are JSON numbers.** Proto-JSON parsers also accept an `int32` or a
  `double` as a string, but no FORA sender emits that form, and accepting it would let
  `"1000"` past a bound of `[0, 1]`.
- **`buf.validate` constraints are carried.** String patterns and lengths, numeric
  bounds, enum `in`/`not_in`/`const` and item counts come from the generator. Two rules
  it cannot express are added: a field whose zero value its own rule rejects is
  `required` (proto-JSON omits a zero value, so an omitted field is that zero value), and
  a `repeated.unique` field carries `uniqueItems`.
- **Enums** accept the value name, which FORA senders emit, or the number of a permitted
  value, which proto-JSON parsers also accept.
- **Not in the schemas:** cross-field rules (CEL) and oneof exclusivity. They cannot be
  expressed per field; servers enforce them, and the SDKs apply the cross-field rules.
  `format` (`date-time`, `duration`) is an annotation unless your validator asserts
  formats.

The schemas are checked against the proto in three ways: the drift gate regenerates them
and compares bytes, `conformance/jsonschema_test.go` checks the file set, the field names
and the unknown-field policy against the compiled descriptors, and both variants must
reach Go protovalidate's verdict on every case of `conformance/corpus/cases.json`, in
Python and in TypeScript.

`jsonschema.go` and this README are hand-written and are not regenerated.
