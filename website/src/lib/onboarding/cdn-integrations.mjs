// Integration choices shown by the preview, keyed by service provider tokens.
export const CDN_INTEGRATIONS = {
	fastly: {
		name: "Fastly",
		scheme: "Ed25519",
		path: "The FORA Edge package checks the Exchange’s signed URLs before allowing access to your licensed content.",
		guidance:
			"The console sets up Cloudflare and CloudFront for you. For Fastly, write to us: we’ll provide the package and guide you through connecting it to your Fastly service, choosing which paths to protect, and testing access before going live.",
		contact: true,
	},
	cloudflare: {
		name: "Cloudflare",
		scheme: "Ed25519",
		path: "Ed25519 signed delivery URLs, verified by the FORA worker in your Cloudflare zone.",
	},
	cloudfront: {
		name: "CloudFront",
		scheme: "Edge verification or RSA",
		path: "The Exchange signs delivery URLs. Your Lambda@Edge function can verify them using the Exchange’s Ed25519 public key, or CloudFront can verify RSA signed URLs natively through a trusted key group configured in your AWS account.",
	},
};

/** The CDN as a visitor would name it, or '' when none was recognized. */
export function cdnName(provider) {
	if (Object.hasOwn(CDN_INTEGRATIONS, provider)) return CDN_INTEGRATIONS[provider].name;
	return provider === "akamai" ? "Akamai" : "";
}

/**
 * The label of the page's links to the publisher contact address: on the CDN
 * card when no network was identified or the console does not set the network
 * up (Fastly, Akamai), and in the note shown when no discovery
 * document could be generated. The page owns the address; this module owns the
 * words.
 */
export const CONTACT_LABEL = "Write to us";

/**
 * The same provider interpretation drives the result badge and configuration.
 * `contact` is CONTACT_LABEL when the outcome needs a link to the publisher
 * contact address, or '' when it needs none; the page owns the address, so this
 * mapping stays pure.
 */
export function cdnPresentation(provider) {
	const integration = Object.hasOwn(CDN_INTEGRATIONS, provider) ? CDN_INTEGRATIONS[provider] : null;
	if (integration)
		return {
			badge: `${integration.name} detected`,
			tone: "ok",
			evidenceIntro: `We recognized ${integration.name}-specific patterns:`,
			title: `Integration path: ${integration.scheme} signed URLs`,
			description: integration.path,
			guidance:
				integration.guidance ??
				"We’ll provide a CDN package and setup instructions tailored to your site. Setup includes choosing the content paths to license and checking that ordinary visitors can still browse normally.",
			contact: integration.contact ? CONTACT_LABEL : "",
		};
	if (provider === "akamai")
		return {
			badge: "Akamai detected",
			tone: "ok",
			evidenceIntro: "We recognized Akamai-specific patterns:",
			title: "Akamai isn’t supported today",
			description:
				"The console sets up Cloudflare and CloudFront for you. FORA’s edge function doesn’t run on Akamai today, so write to us and we’ll help you find the right setup.",
			guidance: "",
			contact: CONTACT_LABEL,
		};
	return {
		badge: "We couldn’t identify your CDN",
		tone: "none",
		evidenceIntro: "We found these network signals:",
		title: "We’ll help you connect your website",
		description:
			"The console sets up CloudFront and Cloudflare for you, and we help Fastly sites connect. If you use another CDN — or no CDN — write to us and we’ll help you find the right setup.",
		guidance: "",
		contact: CONTACT_LABEL,
	};
}
