// Integration choices shown by the preview, keyed by service provider tokens.
export const CDN_INTEGRATIONS = {
	fastly: {
		name: 'Fastly',
		scheme: 'Ed25519',
		path: 'The FORA Edge package checks the Exchange’s signed URLs before allowing access to your licensed content.',
		guidance: 'We’ll provide the package and guide you through connecting it to your Fastly service, choosing which paths to protect, and testing access before going live.',
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
		evidenceIntro: `We recognized ${integration.name}-specific patterns:`,
		title: `Integration path: ${integration.scheme} signed URLs`,
		description: integration.path,
		guidance: integration.guidance ?? 'We’ll provide a CDN package and setup instructions tailored to your site. Setup includes choosing the content paths to license and checking that ordinary visitors can still browse normally.',
	};
	if (provider === 'akamai') return {
		badge: 'Akamai detected', tone: 'ok',
		evidenceIntro: 'We recognized Akamai-specific patterns:',
		title: 'Integration path: Signed delivery URLs',
		description: 'We’ll configure your Akamai integration to check the Exchange’s signed URLs before allowing access to your licensed content.',
		guidance: 'We’ll provide the package and guide you through connecting it to your Akamai service, choosing which paths to protect, and testing access before going live.',
	};
	return {
		badge: 'We couldn’t identify your CDN', tone: 'none',
		evidenceIntro: 'We found these network signals:',
		title: 'We’ll help you connect your website',
		description: 'CloudFront, Cloudflare, and Fastly are supported today. If you use another CDN — or no CDN — leave your email below and we’ll help you find the right setup.',
		guidance: '',
	};
}
