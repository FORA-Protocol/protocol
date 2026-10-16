#!/usr/bin/env python3
# Emit the published per-message JSON Schemas into gen/jsonschema/.
#
# Input: the per-message schemas bufbuild/protoschema-plugins protoc-gen-jsonschema
# v0.6.0 writes (the same pinned run that feeds the Pydantic and Zod models), the
# compiled descriptor, and the required/unique manifests the Go conformance tools emit.
# Output, for every message of the wire contract (fora.v1 and fora.admin.v1):
#
#   <package>.<Message>.schema.json         default: unknown fields are accepted
#   <package>.<Message>.schema.strict.json  strict: additionalProperties false on
#                                           every message object, at every depth
#
# Each file is SELF-CONTAINED: the message schema is the document root, and every
# message it reaches is inlined under `$defs`, keyed by its fully-qualified name. A
# consumer validates against one file with any draft 2020-12 validator, with no
# registry and no network access.
#
# The two variants differ in exactly one thing, the unknown-field policy. Every other
# decision below is shared, because both describe the same wire: canonical proto-JSON,
# as every FORA sender emits it.
#
#   Field names. The proto field names (snake_case). That is the FORA wire naming:
#     the Go server renders with UseProtoNames, the SDKs send proto names, and the
#     canonical signing form is snake_case. protoschema also emits the lowerCamel
#     json_name aliases as `patternProperties`; they are removed, so a camelCase key
#     is an unknown field (refused by the strict variant, ignored by the default one).
#
#   google.protobuf.Struct, Value and ListValue (every `ext` field). Inlined as
#     protoschema renders them: a plain JSON object, any JSON value, a JSON array.
#     They stay open in BOTH variants. The strict variant closes the message objects
#     it builds and never reaches inside a Struct, because the keys of an extension
#     point are not known to the contract. Map fields keep their value schema as
#     `additionalProperties`; that is the map's shape, not an unknown-field policy.
#
#   64-bit integers (int64, uint64 and their fixed/sint forms). A decimal string or a
#     JSON integer. Canonical proto-JSON, and so the Go server, emits the string; the
#     SDKs send a JSON number. When the field has a bound, the bound is encoded in the
#     string arm's pattern too (gte 1 becomes ^0*[1-9][0-9]*$), so the string form
#     cannot carry a value the numeric form refuses. A bound this script cannot encode
#     fails the build instead of shipping a bypass.
#
#   Other numbers (int32, uint32, double, float). A JSON number only. Proto-JSON
#     parsers also accept these as strings, but no FORA sender emits that form, and
#     protoschema puts the numeric bound on the number arm alone: a string arm left
#     standing would accept "1000" for a field bounded to [0, 1]. The canonical
#     "NaN", "Infinity" and "-Infinity" strings stay where protoschema emits them.
#
#   buf.validate constraints. Everything protoschema carries (string patterns and
#     lengths, numeric bounds, enum in/not_in/const, item counts), plus the two rules
#     it cannot express, from the same manifests the generated models use: a field
#     whose zero value its own rule rejects is `required` (proto-JSON omits a zero
#     value, so omission is that zero value), and a repeated.unique field carries
#     `uniqueItems`. Cross-field rules (CEL) and oneof exclusivity are not expressible
#     per field and are not in the schemas; the Go server enforces them.
#
#   Enums. As protoschema emits them: the value name, which every FORA sender uses,
#     or the number of a permitted value, which proto-JSON parsers also accept.
#
# Run by scripts/gen-sdk-types.sh; byte-compared against the committed tree by the drift
# gate (scripts/ci-local.sh, .github/workflows/sdk-types-ci.yml).
import glob
import json
import os
import re
import sys

from google.protobuf import descriptor_pb2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from merge_schema import (  # noqa: E402  (sibling module, same pinned toolchain)
    FLOAT_STR_PATTERN,
    INT_STR_PATTERN,
    load_descriptor,
    mark_required,
    mark_unique,
)

PACKAGES = ("fora.v1", "fora.admin.v1")
SCHEMA = "https://json-schema.org/draft/2020-12/schema"
UINT_STR_PATTERN = r"^[0-9]+$"
NUMERIC_TYPES = ("integer", "number")
BOUND_KEYS = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum")

FD = descriptor_pb2.FieldDescriptorProto
INT64_KINDS = {FD.TYPE_INT64, FD.TYPE_SINT64, FD.TYPE_SFIXED64, FD.TYPE_UINT64, FD.TYPE_FIXED64}
NARROW_KINDS = {
    FD.TYPE_INT32, FD.TYPE_SINT32, FD.TYPE_SFIXED32, FD.TYPE_UINT32, FD.TYPE_FIXED32,
    FD.TYPE_DOUBLE, FD.TYPE_FLOAT,
}

REF_RE = re.compile(r"^((?:fora|google)\.[A-Za-z0-9_.]+)\.schema\.json$")


def field_kinds(fds):
    """fully-qualified message name -> {proto field name -> scalar kind}.

    The kind of a map field is its VALUE's kind (the value schema is where a number sits).
    """
    out = {}

    def walk(prefix, msgs):
        for m in msgs:
            fqn = f"{prefix}.{m.name}"
            entries = {f"{fqn}.{n.name}": n for n in m.nested_type if n.options.map_entry}
            kinds = {}
            for f in m.field:
                entry = entries.get(f.type_name.lstrip("."))
                if entry is not None:
                    kinds[f.name] = next(v.type for v in entry.field if v.name == "value")
                else:
                    kinds[f.name] = f.type
            out[fqn] = kinds
            walk(fqn, [n for n in m.nested_type if not n.options.map_entry])

    for f in fds.file:
        if f.package in PACKAGES:
            walk(f.package, f.message_type)
    return out


def int64_string_pattern(num, where):
    """The decimal-string pattern that admits exactly the integers `num` admits.

    Covers the bounds the contract uses. Anything else stops the build: emitting the
    unbounded pattern next to a bounded number arm would be a bypass.
    """
    bounds = {k: num[k] for k in BOUND_KEYS if k in num}
    if not bounds:
        return INT_STR_PATTERN
    if "enum" in bounds and len(bounds) == 1:
        return "^(" + "|".join(str(int(v)) for v in bounds["enum"]) + ")$"
    lower = bounds.get("minimum")
    if "exclusiveMinimum" in bounds:
        lower = bounds["exclusiveMinimum"] + 1
    if set(bounds) <= {"minimum", "exclusiveMinimum"} and lower == 0:
        return UINT_STR_PATTERN
    if set(bounds) <= {"minimum", "exclusiveMinimum"} and lower == 1:
        return r"^0*[1-9][0-9]*$"
    sys.exit(f"gen_jsonschema: {where}: cannot encode the 64-bit bound {bounds} in the "
             "decimal-string form; extend int64_string_pattern")


def canonical_numbers(node, kind, where):
    """Reduce one numeric field's anyOf to the canonical proto-JSON forms (see header)."""
    if kind not in INT64_KINDS | NARROW_KINDS:
        return node  # an enum's name-or-number union is not a numeric field
    if not isinstance(node, dict) or not isinstance(node.get("anyOf"), list):
        return node
    arms = node["anyOf"]
    nums = [a for a in arms if isinstance(a, dict) and a.get("type") in NUMERIC_TYPES]
    # The string forms of a number: a decimal pattern, or protoschema's catch-all
    # {"type": "string"} for spellings of NaN/Infinity. The canonical NaN/Infinity
    # names are a string arm WITH an enum, and stay.
    numeric_str = [a for a in arms if isinstance(a, dict) and a.get("type") == "string"
                   and "enum" not in a]
    keep = [a for a in arms if a not in numeric_str]
    if kind in INT64_KINDS:
        if len(nums) != 1:
            sys.exit(f"gen_jsonschema: {where}: a split 64-bit range is not supported")
        keep = keep + [{"type": "string", "pattern": int64_string_pattern(nums[0], where)}]
    out = {k: v for k, v in node.items() if k != "anyOf"}
    if len(keep) == 1:
        out.update(keep[0])
    else:
        out["anyOf"] = keep
    return out


def shape_message(schema, fqn, kinds):
    """Field names, numbers and refs for one message schema, shared by both variants."""
    schema = {k: v for k, v in schema.items()
              if k not in ("$id", "$schema", "patternProperties", "additionalProperties")}
    props = schema.get("properties", {})
    if set(props) != set(kinds):
        sys.exit(f"gen_jsonschema: {fqn}: schema properties {sorted(props)} differ from the "
                 f"descriptor fields {sorted(kinds)}")
    shaped = {}
    for name, prop in props.items():
        where = f"{fqn}.{name}"
        prop = canonical_numbers(prop, kinds[name], where)
        for key in ("items", "additionalProperties"):
            if isinstance(prop.get(key), dict):
                prop = dict(prop)
                prop[key] = canonical_numbers(prop[key], kinds[name], where)
        shaped[name] = prop
    schema["properties"] = shaped
    return schema


def resolve_refs(o, wkt, refs):
    """Rewrite protoschema's file refs: a message becomes `#/$defs/<fqn>` (recorded in
    `refs`), a google.protobuf type is inlined from protoschema's own rendering of it."""
    if isinstance(o, dict):
        r = o.get("$ref")
        m = REF_RE.match(r) if isinstance(r, str) else None
        if m:
            name = m.group(1)
            rest = {k: resolve_refs(v, wkt, refs) for k, v in o.items() if k != "$ref"}
            if name.startswith("google.protobuf."):
                if name not in wkt:
                    sys.exit(f"gen_jsonschema: no protoschema rendering of {name}")
                return {**wkt[name], **rest}
            refs.add(name)
            return {"$ref": f"#/$defs/{name}", **rest}
        if r == "#":
            sys.exit("gen_jsonschema: a self-reference ($ref '#') needs bundling support")
        return {k: resolve_refs(v, wkt, refs) for k, v in o.items()}
    if isinstance(o, list):
        return [resolve_refs(x, wkt, refs) for x in o]
    return o


def closure(root, deps):
    seen, todo = set(), [root]
    while todo:
        n = todo.pop()
        for d in deps[n]:
            if d not in seen and d != root:
                seen.add(d)
                todo.append(d)
    return sorted(seen)


def root_refs(o, root):
    """Inside a file whose root IS `root`, a reference to it points at the document root."""
    if isinstance(o, dict):
        if o.get("$ref") == f"#/$defs/{root}":
            o = {**o, "$ref": "#"}
        return {k: root_refs(v, root) for k, v in o.items()}
    if isinstance(o, list):
        return [root_refs(x, root) for x in o]
    return o


def variant(messages, deps, fqn, strict):
    def close(schema):
        return {**schema, "additionalProperties": False} if strict else schema

    suffix = ".schema.strict.json" if strict else ".schema.json"
    doc = {"$schema": SCHEMA, "$id": fqn + suffix, **close(messages[fqn])}
    defs = {d: close(messages[d]) for d in closure(fqn, deps)}
    if defs:
        doc["$defs"] = defs
    return root_refs(doc, fqn)


def assert_no_string_bypass(doc, name):
    """No number arm may keep a string sibling that skips its bound (see header)."""
    bad = []

    def walk(node, path):
        if isinstance(node, dict):
            arms = node.get("anyOf")
            if isinstance(arms, list):
                nums = [a for a in arms if isinstance(a, dict) and a.get("type") in NUMERIC_TYPES]
                strs = [a.get("pattern") for a in arms
                        if isinstance(a, dict) and a.get("type") == "string" and "enum" not in a]
                if nums and FLOAT_STR_PATTERN in strs:
                    bad.append(path)
                if any(k in n for n in nums for k in BOUND_KEYS) and \
                        any(p in (INT_STR_PATTERN, None) for p in strs):
                    bad.append(path)
            for k, v in node.items():
                walk(v, f"{path}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(doc, "")
    if bad:
        sys.exit(f"gen_jsonschema: {name}: a string form bypasses a numeric bound at {bad}")


def main(src_dir, desc_path, required_path, unique_path, out_dir):
    kinds = field_kinds(load_descriptor(desc_path))
    raw = {}
    for f in sorted(glob.glob(os.path.join(src_dir, "*.schema.json"))):
        name = os.path.basename(f)[: -len(".schema.json")]
        raw[name] = json.load(open(f))
    wkt = {n: {k: v for k, v in s.items() if k not in ("$id", "$schema", "title")}
           for n, s in raw.items() if n.startswith("google.protobuf.")}
    fqns = sorted(n for n in raw if n.rsplit(".", 1)[0] in PACKAGES)
    if set(fqns) != set(kinds):
        sys.exit(f"gen_jsonschema: protoschema messages {sorted(set(fqns) ^ set(kinds))} do "
                 "not match the descriptor's contract messages")

    messages, deps = {}, {}
    for fqn in fqns:
        refs = set()
        messages[fqn] = resolve_refs(shape_message(raw[fqn], fqn, kinds[fqn]), wkt, refs)
        deps[fqn] = refs

    # mark_required / mark_unique key by bare message name, the manifests' scheme (the
    # Go generators refuse a cross-package bare-name collision, so the key is unique).
    bare = {fqn.rsplit(".", 1)[1]: messages[fqn] for fqn in fqns}
    mark_required(bare, json.load(open(required_path)))
    mark_unique(bare, json.load(open(unique_path)))

    os.makedirs(out_dir, exist_ok=True)
    for stale in glob.glob(os.path.join(out_dir, "*.json")):
        os.remove(stale)
    for fqn in fqns:
        for strict in (False, True):
            doc = variant(messages, deps, fqn, strict)
            assert_no_string_bypass(doc, doc["$id"])
            with open(os.path.join(out_dir, doc["$id"]), "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2, sort_keys=True, ensure_ascii=False)
                fh.write("\n")
    print(f"wrote {2 * len(fqns)} schemas ({len(fqns)} messages, default + strict) -> {out_dir}")


if __name__ == "__main__":
    main(*sys.argv[1:6])
