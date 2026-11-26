// The SSRF environment isolation every resolver-transport suite shares. Kept out of
// resolvers-harness.ts so each module stays under the file-length limit.

import { afterEach, beforeEach, vi } from "vitest";

/** What decides a resolver's transport outcome from the environment, and so what a test
 * of that outcome must not inherit from the shell that runs it. SKIP_SSRF and
 * ALLOW_INSECURE are the two flags guardedFetchFromEnv reads. The plain transport is
 * Node's global fetch, which reads the proxy variables on a Node release that honours
 * NODE_USE_ENV_PROXY when that is set, so they are cleared too; the guarded transports
 * dial their own undici Agent and read none. */
export const SSRF_ENV = ["SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"];

/** Clear every SSRF_ENV variable before each test of the calling file or describe block
 * and restore the shell's values after it. A test that needs a flag sets it with
 * vi.stubEnv, which the same restore undoes. An empty value is unset to every reader:
 * the two flags read only "1" and "true", and Node's env proxy ignores an empty URL. */
export function isolateSsrfEnv(): void {
	beforeEach(() => {
		for (const name of SSRF_ENV) vi.stubEnv(name, "");
	});
	afterEach(() => {
		vi.unstubAllEnvs();
	});
}
