// Integration choices shown by the preview, keyed by service provider tokens.
export const CDN_INTEGRATIONS = {
	fastly: {
		name: 'Fastly',
		scheme: 'Ed25519',
		path: 'Ed25519 signed delivery URLs, verified by the FORA Compute package on the Fastly service that already fronts your domain.',
	},
	cloudflare: {
		name: 'Cloudflare',
		scheme: 'Ed25519',
		path: 'Ed25519 signed delivery URLs, verified by the FORA worker in your Cloudflare zone.',
	},
	cloudfront: {
		name: 'CloudFront',
		scheme: 'Edge verification or RSA',
		path: 'The Exchange signs delivery URLs. Your Lambda@Edge function can verify them using the Exchange’s Ed25519 public key, or CloudFront can verify RSA signed URLs natively through a trusted key group configured in your AWS account.',
	},
};

/** The same provider interpretation drives the result badge and configuration. */
export function cdnPresentation(provider) {
	const integration = Object.hasOwn(CDN_INTEGRATIONS, provider) ? CDN_INTEGRATIONS[provider] : null;
	if (integration) return {
		badge: `${integration.name} detected`, tone: 'ok',
		title: `Integration path: ${integration.scheme} signed URLs`,
		description: integration.path,
		guidance: 'We’ll provide a CDN package and setup instructions when connections open.',
	};
	if (provider === 'akamai') return {
		badge: 'Akamai detected', tone: 'none',
		title: 'Integration not yet supported',
		description: 'We recognized Akamai, but there is no integration package for it yet.',
		guidance: 'Leave your email below to register your interest.',
	};
	return {
		badge: 'We couldn’t identify your CDN', tone: 'none',
		title: 'Integration to be confirmed',
		description: 'The available evidence did not identify a supported network.',
		guidance: 'Leave your email below to register your interest.',
	};
}
