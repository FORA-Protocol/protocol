import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// gen/ts keeps its own node_modules for its own test run. Without this alias a test
// process here loads THAT copy of zod for the generated schemas and this package's copy
// for everything else: two Zod majors in one run when the two directories disagree, so
// `npm install --no-save zod@4` here would leave the schemas on Zod 3 and test nothing.
// One copy for the whole process, the one this package installed.
export default defineConfig({
	resolve: {
		alias: [{ find: /^zod$/, replacement: fileURLToPath(new URL("./node_modules/zod", import.meta.url)) }],
	},
});
