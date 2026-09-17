// What deploying the edge package looks like on each supported CDN.
//
// The preview service tells the page which CDN fronts a domain; this table
// turns that answer into the integration path, the package to take from the
// console, and the commands to run. Keyed by the provider tokens the service
// returns: cloudfront, cloudflare, fastly.

export const CDN_INTEGRATIONS = {
	fastly: {
		name: 'Fastly',
		scheme: 'Ed25519',
		path: 'Ed25519 signed delivery URLs, verified by the FORA Compute package on the Fastly service that already fronts your domain.',
		take: (domain) => `From the publisher console take <code>fora-edge-fastly.tar.gz</code>. It is built for ${domain} with its config inside; there is nothing to edit. Then, once:`,
		deploy: (domain) => [
			['$', `fastly compute deploy --service <the ${domain} service> --package fora-edge-fastly.tar.gz`],
			['$', 'fastly service-version activate      # the new version goes live'],
			['#', '# in the Fastly UI or CLI: route /news/* and /.well-known/fora.json to the package. Every other path stays as is.'],
			['$', `curl https://${domain}/.well-known/fora.json   # check: the manifest from step 2 comes back`],
		],
	},
	cloudflare: {
		name: 'Cloudflare',
		scheme: 'Ed25519',
		path: 'Ed25519 signed delivery URLs, verified by the FORA worker in your Cloudflare zone.',
		take: () => 'From the publisher console take <code>fora-edge-worker.zip</code>: the worker plus a <code>wrangler.toml</code> with your binding values and routes already filled in. Then, once:',
		deploy: (domain) => [
			['$', `wrangler deploy                      # into the zone that serves ${domain}`],
			['#', `# routes in wrangler.toml: ${domain}/news/* and ${domain}/.well-known/fora.json. Every other path stays as is.`],
			['$', `curl https://${domain}/.well-known/fora.json   # check: the manifest from step 2 comes back`],
		],
	},
	cloudfront: {
		name: 'CloudFront',
		scheme: 'RSA',
		path: 'RSA signed URLs, verified natively by CloudFront through a trusted key group. The Exchange signs; only the public key enters your account.',
		take: () => 'From the publisher console take <code>fora-public-key.pem</code> and <code>fora-edge-lambda.zip</code>. The bundle is built for your distribution with its config inside. Then, once, in us-east-1:',
		deploy: (domain) => [
			['$', 'aws cloudfront create-public-key ... fora-public-key.pem   # then add it to a trusted key group'],
			['#', '# on the /news/* cache behavior: trusted key group = that group, viewer-request = the Lambda@Edge bundle'],
			['#', '# add a cache behavior for /.well-known/fora.json. Every other path stays as is.'],
			['$', `curl https://${domain}/.well-known/fora.json   # check: the manifest from step 2 comes back`],
		],
	},
};
