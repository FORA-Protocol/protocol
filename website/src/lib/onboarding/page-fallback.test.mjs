import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { CDN_INTEGRATIONS } from './cdn-integrations.mjs';

const page = readFileSync(new URL('../../pages/publishers/onboarding.astro', import.meta.url), 'utf8');
test('CDNs render deployment guidance or a registration link when unsupported', () => {
  const render = page.match(/  function renderCdn\([^]*?\n  \}/)[0];
  for (const cdn of [...Object.keys(CDN_INTEGRATIONS), 'none']) {
    const elements = { 'cdn-title': {}, 'cdn-card': {} };
    runInNewContext(`${render}\nrenderCdn();`, {
      $: (id) => elements[id], esc: String, CDN_INTEGRATIONS,
      state: { domain: 'demo.fora-protocol.org', preview: { cdn, evidence: [] } },
    });
    const html = elements['cdn-card'].innerHTML;
    if (cdn === 'none') {
      assert.match(html, /class="btn btn-primary" href="#contact">Start registration<\/a>/);
      assert.doesNotMatch(html, /mailto:|preview is unaffected/);
    } else {
      assert.match(html, /Follow the deployment guide/);
    }
    assert.doesNotMatch(html, /<pre|create-public-key|fora-public-key\.pem|fastly compute deploy|wrangler deploy|Then, once/);
  }
});

const functions = ['renderFailure', 'runPreview'].map((name) =>
  page.match(new RegExp(`  (?:async )?function ${name}\\([^]*?\\n  \\}`))[0],
).join('\n');

test('the temporary preview uses the fixture only in development', async () => {
  const selection = page.match(/const outcome = import\.meta\.env\.DEV[^]*?\n    \}\);/)[0]
    .replace('import.meta.env.DEV', 'development')
    .replace("import('../../lib/onboarding/preview-mock.json')", 'loadMock()');
  for (const development of [true, false]) {
    let requests = 0;
    let imports = 0;
    const outcome = await runInNewContext(`(async () => { ${selection} return outcome; })()`, {
      development,
      loadMock: async () => {
        imports++;
        return { default: JSON.parse(readFileSync(new URL('./preview-mock.json', import.meta.url), 'utf8')) };
      },
      fetchPreview: async () => { requests++; return { ok: true, data: { domain: 'live.example' } }; },
      window: { fetch() {} }, FORA_ONBOARDING_API_BASE: '', built: { body: {} }, controller: {},
    });
    assert.equal(outcome.data.domain, development ? 'publisher.example' : 'live.example');
    if (development) assert.equal(outcome.data.cdn.provider, 'none');
    assert.equal(requests, development ? 0 : 1);
    assert.equal(imports, development ? 1 : 0);
  }
});

test('network failures stay quiet on load and lead to contact only after submitting', async () => {
  for (const scrollToPath of [false, true]) {
    for (const reducedMotion of [false, true]) {
      const scrolls = [];
      const focuses = [];
      const elements = Object.fromEntries(['domain', 'article', 'go', 'status', 'result', 'failure', 'contact', 'contact-name']
        .map((id) => [id, {
          value: 'example.com', hidden: false,
          focus: (options) => focuses.push({ id, ...options }),
          scrollIntoView: (options) => scrolls.push({ id, ...options }),
        }]));
      await runInNewContext(`${functions}\nrunPreview({ scrollToPath });`, {
        $: (id) => elements[id],
        setFieldError() {}, controlState() {},
        previewOnboarding: async () => ({ error: { kind: 'network' } }),
        matchMedia: () => ({ matches: reducedMotion }),
        scrollToPath,
      });
      assert.equal(elements.failure.hidden, true);
      assert.equal(elements.result.hidden, true);
      assert.equal(elements.status.textContent, '');
      assert.equal(elements.go.disabled, false);
      assert.deepEqual(focuses, scrollToPath ? [{ id: 'contact-name', preventScroll: true }] : []);
      assert.deepEqual(scrolls, scrollToPath
        ? [{ id: 'contact', behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' }] : []);
    }
  }
});
