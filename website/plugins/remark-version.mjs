// remark-version resolves the SDK release version from ONE source at build time, and
// refuses a page that spells it out by hand.
//
// Source of truth is the root package.json `version` — one of the authored values
// RELEASING.md advances for every release, alongside the two pyproject versions and
// the TypeScript manifests. Reading it here is the same move proto-schema.mjs makes
// for gen/descriptor.binpb: the site derives from the repository rather than
// restating it.
//
// Two halves, for the same reason remark-proto both renders a table AND fails on an
// unknown reference. Substitution alone would leave every hand-written number that
// already exists, and would not stop the next one being added:
//
//   1. `:sdk-version` (a text directive, so remark-directive parses it) becomes the
//      current version.
//   2. A literal X.Y.Z next to one of the SDK package names FAILS the build when it
//      is not the current version.
//
// Why this exists: three pages carried a hardcoded 1.0.3 next to install
// instructions. They were correct on the day they were written and would have become
// wrong at the next release — telling a reader to install a version that does not
// contain the API described on the same page.
//
// A DIRECTIVE and not `{sdkVersion}`: these are .mdx files, where a brace opens a JSX
// expression, so a brace-delimited placeholder is parsed as JavaScript and breaks the
// build. `::proto-enum{...}` established the directive form here already.
//
// The check is SCOPED to the SDK package names on purpose. The site cites CoMP V1,
// RSL 1.0, C2PA 2.x and protocol v1, none of which move with this version; a rule
// over every X.Y.Z in the tree would flag all of them.
//
// Code spans are deliberately NOT substituted. A directive does not apply inside
// inlineCode (remark-standards skips code spans for the same reason), and a sentinel
// like `@vSDK_VERSION` inside a command a reader copies is worse than the problem. An
// install command names a floating version instead — `go get ...@latest` — and the
// pinned number is stated in the language table, where it can be substituted.
// The stale-literal check DOES read code spans, so a version pinned by hand inside a
// command is still caught.
import { visit } from 'unist-util-visit';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MANIFEST = new URL('../../package.json', import.meta.url);

/** The version every FORA SDK package carries, read once per build. */
export function sdkVersion() {
  const raw = JSON.parse(readFileSync(fileURLToPath(MANIFEST), 'utf8'));
  const version = raw?.version;
  if (typeof version !== 'string' || !/^\d+\.\d+\.\d+/.test(version)) {
    throw new Error(`remark-version: root package.json has no usable version (got ${version})`);
  }
  return version;
}

// A version literal that belongs to THIS release train: one of the published package
// names, or the Go module path, immediately followed by a version. The separator set
// covers the three spellings in use — `@fora-protocol/sdk 1.0.3` in prose,
// `fora-protocol-sdk==1.0.3` in a pip line, and `protocol@v1.0.3` in a go get.
const PINNED = new RegExp(
  '(@fora-protocol/sdk|fora-protocol-sdk|fora-protocol|FORA-Protocol/protocol)' +
    '(\\s+|==|@v|@|\\s+v)(\\d+\\.\\d+\\.\\d+)',
  'g',
);

const DIRECTIVE = 'sdk-version';

/**
 * Every stale pinned version in `text`, as {found, package} entries.
 *
 * Exported for the suite: the failure path is the half that matters, and a guard
 * whose rejection is only reachable through a full site build is a guard nobody
 * breaks on purpose.
 */
export function stalePins(text, version) {
  const out = [];
  for (const m of text.matchAll(PINNED)) {
    if (m[3] !== version) out.push({ found: m[3], package: m[1] });
  }
  return out;
}

export default function remarkVersion() {
  const version = sdkVersion();

  return (tree, file) => {
    // 1. Substitute the directive.
    visit(tree, 'textDirective', (node, index, parent) => {
      if (node.name !== DIRECTIVE || !parent || index == null) return;
      parent.children.splice(index, 1, { type: 'text', value: version });
    });

    // 2. Refuse a hand-written version. inlineCode is included: an install command
    //    that pins by hand is exactly the case that started this.
    const offences = [];
    visit(tree, (n) => n.type === 'text' || n.type === 'inlineCode', (node) => {
      for (const bad of stalePins(node.value, version)) {
        offences.push(`${bad.package} pinned at ${bad.found}`);
      }
    });
    if (offences.length > 0) {
      const where = file?.path ?? 'unknown file';
      throw new Error(
        `remark-version: ${where} names an SDK version that is not the current ` +
          `${version}: ${offences.join('; ')}. Write :sdk-version instead of the ` +
          `number, or use a floating version in a command (go get ...@latest).`,
      );
    }
  };
}
