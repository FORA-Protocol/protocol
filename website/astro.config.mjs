// @ts-check
import { defineConfig, envField } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightMermaid from '@pasqal-io/starlight-client-mermaid';
import starlightLinksValidator from 'starlight-links-validator';
import remarkDirective from 'remark-directive';
import remarkExample from './plugins/remark-example.mjs';
import remarkProto from './plugins/remark-proto.mjs';
import remarkStandards from './plugins/remark-standards.mjs';
import remarkVersion from './plugins/remark-version.mjs';

export default defineConfig({
	vite: {
		server: {
			// Dev only. The preview service does not answer cross-origin calls from
			// localhost, so `.env.development` points the page at this path and
			// the dev server forwards it to the deployed service.
			proxy: {
				'/onboarding': { target: 'https://pub-onboarding.demo.fora-protocol.org', changeOrigin: true },
			},
		},
	},
	env: {
		schema: {
			// Base URL of the publisher onboarding preview service, including any
			// path prefix it is mounted under. The onboarding page appends
			// `/v1/preview`. Declared here rather than hardcoded so a host or
			// prefix change is a build-environment value, not a code edit; the
			// default is the deployed service, so a clean checkout builds and
			// runs with nothing set. Astro loads env with an empty prefix, so the
			// name needs no `PUBLIC_` and a plain build variable is picked up.
			FORA_ONBOARDING_API_BASE: envField.string({
				context: 'client',
				access: 'public',
				default: 'https://pub-onboarding.demo.fora-protocol.org/onboarding',
			}),
			// Where the onboarding page's register button and the publisher guide
			// send a publisher: the console root, which signs a visitor in, or lets
			// them create an account, before anything else. The default is the
			// console's address on fora-protocol.org, which redirects to wherever
			// the console runs, so moving the console changes that redirect rather
			// than this site. Astro validates a value set in the build environment
			// but never the default, so the default must itself be an https URL.
			FORA_PUBLISHER_CONSOLE_URL: envField.string({
				context: 'client',
				access: 'public',
				url: true,
				startsWith: 'https://',
				default: 'https://console.fora-protocol.org/',
			}),
			// Where a publisher reaches us when the preview cannot take them further:
			// a CDN the preview does not recognize, or a domain it could not
			// generate a discovery document for.
			FORA_PUBLISHER_CONTACT_URL: envField.string({
				context: 'client',
				access: 'public',
				default: 'mailto:publishers@fora-protocol.org',
			}),
		},
	},
	markdown: {
		// remarkExample: replace ::example{file=… regions=…|fence=…} with the named slice
		//   of a file an existing gate compiles or runs — so a code block on the site
		//   cannot show code that does not build. Runs FIRST so the block it produces is
		//   an ordinary code node to everything after it. See plugins/remark-example.mjs.
		// remarkProto: render proto-derived tables (::proto-enum / ::proto-vocab) from the
		//   descriptor AND autolink/validate every proto reference in one mdast pass — so a
		//   reference in a rendered table links like one in prose, and an unknown reference
		//   fails the build. See plugins/remark-proto.mjs + proto-schema.mjs.
		// remarkVersion: resolve :sdk-version from the root package.json AND fail the build
		//   on a hand-written SDK version that has gone stale. Runs after remarkProto so a
		//   generated table can carry the directive too, and before remarkStandards so the
		//   text it produces is a plain version rather than something to link.
		// remarkStandards: link the first mention of each external standard (RFC NNNN, C2PA,
		//   …) to its canonical source. Runs after remarkProto so generated tables link too.
		remarkPlugins: [remarkDirective, remarkExample, remarkProto, remarkVersion, remarkStandards],
	},
	integrations: [
		starlight({
			title: 'FORA Protocol',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/FORA-Protocol/protocol' }],
			plugins: [starlightMermaid(), starlightLinksValidator()],
			components: {
				Footer: './src/components/Footer.astro',
			},
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'What is FORA?', slug: 'getting-started/what-is-fora' },
						{ label: 'Live Demo: First License', slug: 'getting-started/poc-walkthrough' },
						{ label: 'Live Demo: Music', slug: 'getting-started/live-demo-music' },
						{ label: 'For Providers', slug: 'getting-started/for-providers' },
						{ label: 'Publisher Onboarding', slug: 'getting-started/publisher-onboarding' },
						{ label: 'For Content Marketplaces', slug: 'getting-started/existing-marketplace' },
						{ label: 'For AI Agents', slug: 'getting-started/for-ai-agents' },
						{ label: 'How Money Flows', slug: 'getting-started/how-money-flows' },
					],
				},
				{
					label: 'Protocol',
					items: [
						{ label: 'Transaction Flow', slug: 'protocol/transaction-flow' },
						{ label: 'Standards Layering', slug: 'protocol/standards-layering' },
						{ label: 'Discovery Paths', slug: 'protocol/discovery-paths' },
						{ label: 'JSONL Ingestion', slug: 'protocol/jsonl-ingestion' },
						{ label: 'Exchange Manifest', slug: 'protocol/exchange-manifest' },
						{ label: 'Resource Attestation', slug: 'protocol/content-attestation' },
						{ label: 'Authentication', slug: 'protocol/authentication' },
						{ label: 'Role Composition', slug: 'protocol/role-composition' },
						{ label: 'Dispute Resolution', slug: 'protocol/dispute-resolution' },
						{ label: 'Extension Profiles', slug: 'protocol/extension-profiles' },
						{ label: 'Ext: News', slug: 'protocol/ext-news' },
						{ label: 'Ext: Academic', slug: 'protocol/ext-academic' },
						{ label: 'Ext: Legal', slug: 'protocol/ext-legal' },
						{ label: 'Ext: CoMP', slug: 'protocol/ext-comp' },
						{ label: 'Ext: C2PA', slug: 'protocol/ext-c2pa' },
					],
				},
				{
					label: 'Components',
					items: [
						{
							label: 'Identity Service',
							items: [
								{ label: 'Overview', slug: 'components/identity/overview' },
							],
						},
						{
							label: 'Edge Function',
							items: [
								{ label: 'Overview', slug: 'components/edge-function/overview' },
								{ label: 'CDN Adapters', slug: 'components/edge-function/cdn-adapters' },
								{ label: 'Signed URL Verification', slug: 'components/edge-function/signed-url-verification' },
								{ label: 'Bot Detection', slug: 'components/edge-function/bot-detection' },
								{ label: 'Composition', slug: 'components/edge-function/composition' },
								{ label: 'Deployment', slug: 'components/edge-function/deployment' },
							],
						},
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Proto: FORA v1', slug: 'reference/proto-fora' },
						{ label: 'Proto: Admin v1', slug: 'reference/proto-admin' },
						{ label: 'Standards & References', slug: 'reference/standards' },
						{ label: 'fora.json Example', slug: 'reference/fora-json-example' },
						{ label: 'Changelog', slug: 'reference/changelog' },
					],
				},
			],
		}),
	],
});

