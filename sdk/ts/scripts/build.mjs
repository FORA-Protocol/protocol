// Build the publishable @fora-protocol/sdk package into dist/.
//
// 1. Stage: copy gen/ts (wire, vocab) and sdk/ts (src, core, client, hono,
//    resolvers) into .stage/ with the same relative layout, so every
//    ../../../gen/ts import keeps resolving inside the package.
// 2. Compile .stage/ with tsconfig.build.json (NodeNext, .ts import suffixes
//    rewritten to .js, declarations) into dist/.
// 3. Write the staged release manifest dist/package.json: the sdk/ts export map
//    pointed at the compiled files, plus the generated schemas and vocabulary.
//    This manifest is the only one named @fora-protocol/sdk; npm pack / publish
//    run against dist/.
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const pkgDir = dirname(dirname(fileURLToPath(import.meta.url))); // sdk/ts
const repo = join(pkgDir, "..", "..");
const stage = join(pkgDir, ".stage");
const dist = join(pkgDir, "dist");

const sdkPkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
const genPkg = JSON.parse(readFileSync(join(repo, "gen/ts/package.json"), "utf8"));

rmSync(stage, { recursive: true, force: true });
rmSync(dist, { recursive: true, force: true });
for (const dir of ["gen/ts/wire", "gen/ts/vocab"]) cpSync(join(repo, dir), join(stage, dir), { recursive: true });
for (const dir of ["src", "core", "client", "hono", "resolvers"]) cpSync(join(pkgDir, dir), join(stage, "sdk/ts", dir), { recursive: true });

execFileSync("npx", ["tsc", "-p", "tsconfig.build.json"], { cwd: pkgDir, stdio: "inherit" });

// The generated schemas' types are shipped as TypeScript SOURCE, not as emitted
// declarations. A declaration file freezes the Zod class generics of the Zod major
// it was compiled against (ZodObject has five type parameters in Zod 3 and two in
// Zod 4), so it cannot serve the declared `zod ^3 || ^4` peer range; the source
// infers against whichever Zod the consumer installed, as the git-install path
// always has. The `.ts` import suffixes become `.js` so the copies resolve under
// NodeNext without allowImportingTsExtensions; every `.js` next to them exists.
// The sdk/ts declarations keep their `.ts` specifiers for the schemas (tsc does not
// rewrite specifiers inside `.d.ts` output); TypeScript resolves those to these
// `.ts` files once the `.d.ts` files are gone.
const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name));
for (const file of walk(join(stage, "gen/ts")).filter((f) => f.endsWith(".ts"))) {
  const src = readFileSync(file, "utf8").replace(/(from\s+["'])(\.{1,2}\/[^"']+)\.ts(["'])/g, "$1$2.js$3");
  writeFileSync(join(dist, "gen/ts", file.slice(join(stage, "gen/ts").length + 1)), src);
}
for (const file of walk(join(dist, "gen/ts")).filter((f) => f.endsWith(".d.ts"))) rmSync(file);
rmSync(stage, { recursive: true, force: true });

// "./src/x.ts" under prefix "sdk/ts" -> { types: "./sdk/ts/src/x.d.ts", default: "./sdk/ts/src/x.js" }
// "./wire/x.ts" under prefix "gen/ts" -> { types: "./gen/ts/wire/x.ts",  default: "./gen/ts/wire/x.js" }
const compiled = (prefix, target, typesExt) => {
  const base = `./${prefix}/${target.slice(2, -".ts".length)}`;
  return { types: `${base}${typesExt}`, default: `${base}.js` };
};
const exports = {};
for (const [subpath, target] of Object.entries(sdkPkg.exports)) exports[subpath] = compiled("sdk/ts", target, ".d.ts");
for (const [subpath, target] of Object.entries(genPkg.exports)) exports[subpath] = compiled("gen/ts", target, ".ts");

const manifest = {
  name: "@fora-protocol/sdk",
  version: sdkPkg.version,
  description:
    "FORA protocol SDK for TypeScript: the generated wire schemas (Zod) and vocabulary, the IO-free protocol mechanics (signing, verification, canonicalization), the key/endpoint resolvers and the Connect-unary JSON client.",
  license: "Apache-2.0",
  repository: { type: "git", url: "git+https://github.com/FORA-Protocol/protocol.git", directory: "sdk/ts" },
  homepage: "https://fora-protocol.org",
  type: "module",
  files: ["gen", "sdk"],
  exports,
  dependencies: sdkPkg.dependencies,
  peerDependencies: sdkPkg.peerDependencies,
  peerDependenciesMeta: sdkPkg.peerDependenciesMeta,
  publishConfig: { access: "public" },
};
mkdirSync(dist, { recursive: true });
writeFileSync(join(dist, "package.json"), JSON.stringify(manifest, null, 2) + "\n");
cpSync(join(repo, "LICENSE"), join(dist, "LICENSE"));
cpSync(join(pkgDir, "README.md"), join(dist, "README.md"));
console.log(`built @fora-protocol/sdk@${manifest.version} into ${dist}`);
