import test from 'node:test';
import assert from 'node:assert/strict';
import * as integrations from './cdn-integrations.mjs';

function presentation(provider) {
  assert.equal(typeof integrations.cdnPresentation, 'function', 'CDN presentation must expose a pure provider mapping');
  const result = integrations.cdnPresentation(provider);
  for (const field of ['badge', 'tone', 'title', 'description', 'guidance']) {
    assert.equal(typeof result[field], 'string', `${field} must be text`);
    assert.ok(result[field].trim(), `${field} must not be empty`);
  }
  return result;
}

test('supported providers identify their distinct integration and promise future instructions', () => {
  const descriptions = new Set();
  for (const [provider, name, integration] of [
    ['cloudfront', 'CloudFront', /Lambda@Edge/],
    ['cloudflare', 'Cloudflare', /worker/i],
    ['fastly', 'Fastly', /Compute/],
  ]) {
    const result = presentation(provider);
    assert.ok(result.badge.includes(name), `${provider} badge must name its CDN`);
    assert.match(result.description, integration);
    assert.match(result.guidance, /packages?/i);
    assert.match(result.guidance, /instructions?/i);
    assert.match(result.guidance, /will|[’']ll|later|future/i);
    assert.doesNotMatch(result.guidance, /\bdownload\b|\bdeploy\b|follow the deployment guide|publisher console/i);
    descriptions.add(result.description);
  }
  assert.equal(descriptions.size, 3);
});

test('CloudFront preserves both verification choices without selecting a default', () => {
  const result = presentation('cloudfront');
  assert.equal(result.title, 'Integration path: Edge verification or RSA signed URLs');
  assert.equal(result.description, 'The Exchange signs delivery URLs. Your Lambda@Edge function can verify them using the Exchange’s Ed25519 public key, or CloudFront can verify RSA signed URLs natively through a trusted key group configured in your AWS account.');
  assert.doesNotMatch(result.guidance, /default|recommend.*RSA|use RSA/i);
});

test('Akamai is recognized but has no integration package yet', () => {
  const result = presentation('akamai');
  assert.match(result.badge, /Akamai/);
  assert.match(`${result.title} ${result.description} ${result.guidance}`, /(?:no|not|yet).*package|package.*(?:not|yet)/i);
  assert.notEqual(result.badge, presentation('none').badge);
  assert.doesNotMatch(`${result.description} ${result.guidance}`, /\bdownload\b|\bdeploy\b|start registration/i);
});

test('absent, unexpected, prototype and hostile provider tokens share an honest unknown outcome', () => {
  const unknown = presentation('none');
  assert.equal(unknown.badge, 'We couldn’t identify your CDN');
  assert.match(unknown.guidance, /interest|let us know|contact/i);
  assert.doesNotMatch(`${unknown.title} ${unknown.description} ${unknown.guidance}`, /no CDN|without a CDN|direct.origin|start registration/i);
  for (const provider of [undefined, null, '', 'unknown', 'unexpected-provider', 'constructor', 'toString', '__proto__', '<img src=x onerror=alert(1)>']) {
    assert.deepEqual(presentation(provider), unknown, `Unexpected provider ${String(provider)} must not be echoed or treated as detected`);
  }
});
