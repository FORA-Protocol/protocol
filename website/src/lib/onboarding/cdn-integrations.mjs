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
		take: () => 'Download your edge package (<code>fora-edge-fastly.tar.gz</code>) from the publisher console. It includes the configuration for your Fastly service.',
		guidance: 'Follow the deployment guide to connect the package to your Fastly service, configure your origin, and route your licensed content and discovery document through the package. Before going live, check that your discovery document is publicly accessible, ordinary visitors can browse normally, and AI agents need valid paid access to licensed content.',
	},
	cloudflare: {
		name: 'Cloudflare',
		scheme: 'Ed25519',
		path: 'Ed25519 signed delivery URLs, verified by the FORA worker in your Cloudflare zone.',
		take: () => 'Download your edge package (<code>fora-edge-worker.zip</code>) from the publisher console. It includes the worker and a <code>wrangler.toml</code> file with the configuration for your Cloudflare zone.',
		guidance: 'Follow the deployment guide to deploy the worker and route your licensed content and discovery document through it. Before going live, check that your discovery document is publicly accessible, ordinary visitors can browse normally, and AI agents need valid paid access to licensed content.',
	},
	cloudfront: {
		name: 'CloudFront',
		scheme: 'Edge verification or RSA',
		path: 'The Exchange signs delivery URLs. Your Lambda@Edge function can verify them using the Exchange’s Ed25519 public key, or CloudFront can verify RSA signed URLs natively through a trusted key group configured in your AWS account.',
		take: () => 'Download your edge package (<code>fora-edge-lambda.zip</code>) from the publisher console. It includes the configuration for your distribution.',
		guidance: 'Follow the deployment guide to connect the package to your CloudFront distribution and configure access verification. Before going live, check that your discovery document is publicly accessible, ordinary visitors can browse normally, and AI agents need valid paid access to licensed content.',
	},
};
