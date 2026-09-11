// remark-example pulls a documentation code block out of a file the compiler checks,
// so a page cannot show code that does not build.
//
//   ::example{file="sdk/go/examples/agent/agent.go" regions="imports,client" lang="go"}
//
// Why this exists: the agent-SDK pages carried four hand-kept copies of the Go agent
// example and one of the TypeScript one. They had already drifted. One Go copy called
// len() on a struct and would not compile; the TypeScript copy read `content.length`
// on a Content that has no `length`, which made the usage report bill nothing; and a
// third block named two Go helpers that do not exist. Nothing on the site could catch
// any of it, because the site's copies were the only copies nothing compiled.
//
// Now there is one copy per language, in a file an existing gate already builds:
//
//   sdk/go/examples/agent/agent.go  -> `go build ./...`, step 5 of scripts/ci-local.sh
//   sdk/ts/examples/agent.ts        -> `tsc -p tsconfig.json --strict --noEmit`
//   sdk/python/README.md            -> sdk/python/tests/test_readme_agent_example.py,
//                                      which extracts the block and RUNS it
//
// A page names a region of one of those files and gets its text verbatim.
//
// REGIONS, not whole files. Each page shows a different slice of the same flow —
// Fetch Flow walks all four verbs, Budget & Reporting shows only the report, For AI
// Agents takes the client and the discover call one at a time — and the example file
// has a preamble (a package clause, a function signature, the identity parameters)
// that no page should show. A region is delimited by two comment lines:
//
//   // fora:example client
//   ...the lines a page shows...
//   // fora:/example client
//
// The marker lines never reach the page. The comment syntax does not matter: the
// markers are found by the token, so Go, TypeScript and Python all work, and a
// language whose comment syntax is different needs no change here.
//
// FENCES, for the file a reader also reads. sdk/python/README.md cannot include
// anything — PyPI renders it as static markdown — so the executed Python example has
// to live in the README as literal text. It already carries an HTML-comment anchor
// that the executing test keys on, and it renders as nothing:
//
//   <!-- fora:agent-example -->
//   ```python
//   ...the executed program...
//   ```
//
// ::example{file="sdk/python/README.md" fence="agent-example" lang="python"} takes
// that block, so the site shows the program a test actually runs rather than a
// paraphrase of it. The anchor must appear exactly once, which is what turns a copied
// block into a loud failure instead of a silently wrong one.
//
// EVERY failure throws. An unreadable file, a missing region, an empty region, a
// region opened twice or never closed — each fails the build naming the page, the
// file and the region, the same way remark-proto fails on an unknown proto reference.
// That is the property the whole mechanism rests on: a region cannot be renamed or
// deleted in the SDK while a page still asks for it.
import { visit } from 'unist-util-visit';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Paths in a directive are repo-relative, because that is how a reader of the .mdx
// finds the file. website/ is one level down.
const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

const OPEN = /(^|\W)fora:example\s+([A-Za-z0-9_-]+)\s*$/;
const CLOSE = /(^|\W)fora:\/example\s+([A-Za-z0-9_-]+)\s*$/;

const cache = new Map();

/** regionsOf parses every fora:example region out of one file's text. */
export function regionsOf(source, file) {
  const found = new Map();
  const open = new Map();
  source.split('\n').forEach((line, i) => {
    const o = OPEN.exec(line);
    if (o) {
      const name = o[2];
      if (open.has(name)) {
        throw new Error(`${file}: region "${name}" is opened twice (line ${open.get(name) + 1} and line ${i + 1})`);
      }
      if (found.has(name)) {
        throw new Error(`${file}: region "${name}" is defined twice; a region name must be unique within a file`);
      }
      open.set(name, i);
      return;
    }
    const c = CLOSE.exec(line);
    if (c) {
      const name = c[2];
      if (!open.has(name)) {
        throw new Error(`${file}: region "${name}" is closed at line ${i + 1} without being opened`);
      }
      found.set(name, { start: open.get(name) + 1, end: i });
      open.delete(name);
    }
  });
  if (open.size > 0) {
    const names = [...open.keys()].sort().join(', ');
    throw new Error(`${file}: region(s) never closed: ${names}. Add a "fora:/example <name>" line.`);
  }
  const lines = source.split('\n');
  const out = new Map();
  for (const [name, { start, end }] of found) {
    out.set(name, dedent(lines.slice(start, end)));
  }
  return out;
}

/** dedent strips the common leading whitespace, so a region taken from inside a
 * function body renders flush left the way a reader would paste it. */
function dedent(lines) {
  const body = lines.filter((l) => l.trim() !== '');
  if (body.length === 0) return '';
  const indent = Math.min(...body.map((l) => /^[ \t]*/.exec(l)[0].length));
  return lines.map((l) => (l.trim() === '' ? '' : l.slice(indent))).join('\n').replace(/^\n+|\n+$/g, '');
}

/** fencedBlock returns the fenced code block that follows an <!-- fora:NAME --> anchor. */
export function fencedBlock(file, name, page = '<unknown page>') {
  const lines = read(file).split('\n');
  const anchor = `<!-- fora:${name}`;
  const at = lines.reduce((acc, line, i) => (line.startsWith(anchor) ? [...acc, i] : acc), []);
  if (at.length !== 1) {
    throw new Error(`${page}: expected exactly one "${anchor}" anchor in ${file}, found ${at.length}. ` +
      `A second copy of the block means the site and the test would show different code.`);
  }
  const open = at[0] + 1;
  if (!lines[open]?.startsWith('```')) {
    throw new Error(`${page}: the "${anchor}" anchor in ${file} is not immediately followed by a fenced code block.`);
  }
  const close = lines.indexOf('```', open + 1);
  if (close === -1) throw new Error(`${page}: the block after "${anchor}" in ${file} is never closed.`);
  const body = lines.slice(open + 1, close).join('\n');
  if (body.trim() === '') throw new Error(`${page}: the block after "${anchor}" in ${file} is empty.`);
  return body;
}

function read(file) {
  try {
    return readFileSync(new URL(file, `file://${repoRoot}`), 'utf8');
  } catch (err) {
    throw new Error(`::example names file "${file}", which cannot be read (${err.code ?? err.message}). ` +
      `The path is relative to the repository root.`);
  }
}

function load(file) {
  if (cache.has(file)) return cache.get(file);
  const regions = regionsOf(read(file), file);
  cache.set(file, regions);
  return regions;
}

export default function remarkExample() {
  return (tree, vfile) => {
    const page = vfile?.path ?? '<unknown page>';
    visit(tree, (n) => n.type === 'leafDirective' || n.type === 'containerDirective', (node, index, parent) => {
      if (node.name !== 'example' || !parent || index == null) return;
      const { file, regions, fence, lang } = node.attributes ?? {};
      if (!file) throw new Error(`${page}: ::example needs a file= attribute`);
      if (!lang) throw new Error(`${page}: ::example{file=${file}} needs a lang= attribute`);
      if (!regions && !fence) {
        throw new Error(`${page}: ::example{file=${file}} needs a regions= or a fence= attribute`);
      }
      if (regions && fence) {
        throw new Error(`${page}: ::example{file=${file}} sets both regions= and fence=; it takes one or the other`);
      }

      if (fence) {
        parent.children.splice(index, 1, { type: 'code', lang, value: fencedBlock(file, fence, page) });
        return;
      }

      const available = load(file);
      const wanted = regions.split(',').map((r) => r.trim()).filter((r) => r !== '');
      const blocks = wanted.map((name) => {
        const body = available.get(name);
        if (body === undefined) {
          const known = [...available.keys()].sort().join(', ') || '(none)';
          throw new Error(`${page}: ::example asks ${file} for region "${name}", which it does not define. ` +
            `Regions in that file: ${known}.`);
        }
        if (body === '') {
          throw new Error(`${page}: region "${name}" of ${file} is empty, so the page would render an empty block.`);
        }
        return body;
      });

      parent.children.splice(index, 1, { type: 'code', lang, value: blocks.join('\n\n') });
    });
  };
}
