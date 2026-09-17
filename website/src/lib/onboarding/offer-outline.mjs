// The offer an agent receives, as an outline a person can read.
//
// The Exchange answers an agent with an Offer (fora.v1.Offer): the resource,
// what may be done with it, what it costs and who signed for it. That message
// is what this page shows -- not the catalog record the ingest side stores,
// which answers a different question and is nobody's job to read here.
//
// The walk is driven by the offer itself rather than a fixed list of fields, so
// everything the Exchange sends is on screen and a field added to the message
// later appears without a change here. A handful of fields read better as prose
// than as data, and those are the ones this module knows by name.
//
// Pure: it takes the offer as canonical proto-JSON and returns plain nodes.
// Nothing here builds markup.

import { USE_LABELS } from './terms-vocab.mjs';

/** Field names as a reader sees them. Anything missing falls back to the name. */
const FIELD_LABELS = {
	// Offer
	offer_id: 'offer id',
	title: 'title',
	pricing: 'price',
	delivery_method: 'delivery',
	reporting: 'reporting',
	expires_at: 'expires',
	identity: 'identity',
	exchange: 'sold by',
	signature: 'signature',
	signature_algorithm: 'signed with',
	subscription_id: 'subscription',
	iab_categories: 'IAB categories',
	attestations: 'attestations',
	data_as_of: 'data as of',
	subscription_quota: 'subscription quota',
	previews: 'previews',
	terms: 'terms',
	ext: 'extensions',
	ext_critical: 'critical extensions',
	// LicenseTerm
	license: 'license',
	semantics: 'semantics',
	restrictions: 'condition',
	quotas: 'quotas',
	obligations: 'obligation',
	scopes: 'scopes',
	part_label: 'part',
	// ResourceIdentity
	canonical_url: 'canonical url',
	doi: 'DOI',
	iptc_guid: 'IPTC GUID',
	isni: 'ISNI',
	content_hash: 'content hash',
	hash_method: 'hash method',
	// ReportingObligation
	required: 'required',
	window: 'window',
	endpoint: 'endpoint',
	required_fields: 'required fields',
	// License
	uri: 'uri',
	id: 'id',
	name: 'name',
	immutable: 'immutable',
	// Quota
	metric: 'metric',
	limit: 'limit',
	// Preview
	url: 'url',
	media_type: 'media type',
	width: 'width',
	height: 'height',
	duration: 'duration',
	size: 'size',
};

/** The order the offer's own fields read best in. Anything else follows. */
const OFFER_ORDER = [
	'title', 'offer_id', 'exchange', 'pricing', 'delivery_method', 'expires_at',
	'terms', 'identity', 'previews', 'reporting', 'subscription_id',
	'subscription_quota', 'iab_categories', 'attestations', 'data_as_of',
	'ext', 'ext_critical', 'signature_algorithm', 'signature',
];

/** The order a term's fields read best in. */
const TERM_ORDER = ['restrictions', 'pricing', 'obligations', 'license', 'quotas', 'scopes', 'semantics', 'part_label'];

/** Enum prefixes proto-JSON emits, longest first so the match is unambiguous. */
const ENUM_PREFIXES = [
	'OBLIGATION_TRIGGER_', 'OBLIGATION_KIND_', 'RESTRICTION_KIND_', 'DELIVERY_METHOD_',
	'PRICING_MODEL_', 'TERM_SEMANTICS_', 'RESOURCE_MUTABILITY_', 'INGESTION_SOURCE_',
	'QUOTA_WINDOW_', 'SIGNATURE_ALGORITHM_',
];

/** Fields whose value is a hex blob nobody reads in full. */
const ABBREVIATED = new Set(['signature', 'content_hash']);

/** A use token as a reader sees it. */
export function useLabel(token) {
	if (USE_LABELS[token]) return USE_LABELS[token];
	return humanise(token);
}

/**
 * Whether a string is a proto-JSON enum value. They are SCREAMING_SNAKE and
 * always carry at least one underscore, which is what separates them from an
 * ordinary all-caps word like a title or a currency code.
 */
export function isEnumValue(value) {
	return /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(String(value ?? ''));
}

/** A field name, or any token, as words. */
export function humanise(token) {
	const text = String(token ?? '').replace(/[-_]+/g, ' ').trim();
	return text === '' ? '' : text.charAt(0).toUpperCase() + text.slice(1);
}

/** Join a list the way a sentence does: "a, b and c". */
export function sentenceList(items) {
	const parts = items.filter((item) => item !== '');
	if (parts.length === 0) return '';
	if (parts.length === 1) return parts[0];
	return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

/**
 * An enum value as words: DELIVERY_METHOD_DIRECT reads "direct". A value whose
 * prefix this module does not know still reads, just with more of it.
 */
export function enumLabel(value) {
	const text = String(value ?? '');
	if (!isEnumValue(text)) return text;
	const prefix = ENUM_PREFIXES.find((candidate) => text.startsWith(candidate));
	const rest = prefix ? text.slice(prefix.length) : text;
	if (rest === '' || rest === 'UNSPECIFIED') return 'not stated';
	return rest.toLowerCase().replace(/_/g, ' ');
}

/**
 * The metering unit as a price reads it.
 *
 * The registered pricing units are plural -- "accesses", "fetches", "pages" --
 * because they count what was metered. A unit price talks about one of them,
 * so "EUR 0.02 per accesses" has to become "per access". The token itself is
 * untouched; this is display text, the same as a use label.
 */
export function singularUnit(token) {
	const text = String(token ?? '').trim().replace(/-/g, ' ');
	if (text === '') return '';
	if (/(?:ch|sh|s|x|z)es$/.test(text)) return text.slice(0, -2);
	if (/[^s]s$/.test(text)) return text.slice(0, -1);
	return text;
}

/** A timestamp as a reader sees it, from the RFC 3339 proto-JSON emits. */
export function timeLabel(value) {
	const text = String(value ?? '');
	const at = new Date(text);
	if (Number.isNaN(at.getTime())) return text;
	return `${at.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** The head and tail of a long opaque value, so it is recognisable but short. */
export function abbreviate(value, keep = 8) {
	const text = String(value ?? '');
	return text.length <= keep * 2 + 1 ? text : `${text.slice(0, keep)}…${text.slice(-4)}`;
}

/** What a term allows and refuses, in one sentence. */
export function conditionSentence(term) {
	const restrictions = Array.isArray(term?.restrictions) ? term.restrictions : [];
	const functions = restrictions.find((r) => r?.kind === 'RESTRICTION_KIND_FUNCTION') ?? restrictions[0] ?? {};
	const permitted = (Array.isArray(functions.permitted) ? functions.permitted : []).map(useLabel);
	const prohibited = (Array.isArray(functions.prohibited) ? functions.prohibited : []).map(useLabel);

	const clauses = [];
	if (permitted.length) clauses.push(`${sentenceList(permitted)} allowed`);
	if (prohibited.length) clauses.push(`${sentenceList(prohibited)} not allowed`);
	if (clauses.length === 0) return 'no use restrictions stated';
	return clauses.join('; ');
}

/** What the term costs, in one line. */
export function priceSentence(pricing) {
	if (!pricing || typeof pricing !== 'object') return 'not stated';
	if (pricing.model === 'PRICING_MODEL_FREE') return 'free';

	const model = enumLabel(pricing.model);
	const amount = [pricing.currency, pricing.rate].filter(Boolean).join(' ');
	if (amount === '') return model || 'not stated';
	if (pricing.unit) return `${amount} per ${singularUnit(pricing.unit)}`;
	return model === 'flat' ? `${amount}, flat fee` : amount;
}

/** When an obligation bites, spelled out. */
const OBLIGATION_TRIGGERS = {
	'OBLIGATION_TRIGGER_ON_USE': 'on every use',
	'OBLIGATION_TRIGGER_ON_PUBLICATION': 'on publication',
	'OBLIGATION_TRIGGER_ON_REQUEST': 'on request',
};

/** One obligation, as a line. */
export function obligationSentence(obligation) {
	const kind = enumLabel(obligation?.kind);
	const trigger = OBLIGATION_TRIGGERS[obligation?.trigger] ?? enumLabel(obligation?.trigger);
	const detail = typeof obligation?.detail === 'string' ? obligation.detail.trim() : '';
	const head = [kind, trigger].filter((part) => part && part !== 'not stated').join(' ');
	return detail === '' ? head : `${head} — ${detail}`;
}

/** One quota, as a line. */
export function quotaSentence(quota) {
	const metric = humanise(quota?.metric).toLowerCase();
	const limit = quota?.limit ?? quota?.limit === 0 ? String(quota.limit) : '';
	const window = enumLabel(quota?.window);
	const head = [limit, metric].filter(Boolean).join(' ');
	return window && window !== 'not stated' ? `${head} per ${window}` : head;
}

/**
 * What stands in place of the offer when the page could not be read.
 *
 * The service names the case in page.unreadable; this turns it into the
 * sentence a publisher reads. Bot protection gets its own wording because it is
 * the one refusal they cannot fix by changing the page: their readers reach it
 * and this check does not.
 */
export function unreadableSentence(unreadable) {
	const status = Number(unreadable?.status) || 0;
	switch (unreadable?.reason) {
		case 'bot_protection':
			return 'The network in front of your site turned our check away as automated traffic, '
				+ 'so we could not read this page. Your readers reach it; we do not.';
		case 'refused':
			return `Your site declined to serve this page${status ? ` and answered ${status}` : ''}, `
				+ 'so we could not read it.';
		case 'not_found':
			return 'There is nothing at that address, so there is no page for us to read.';
		case 'server_error':
			return `Your site answered ${status || 'an error'} for this page, so we could not read it.`;
		default:
			return `Your site answered ${status || 'something other than a page'} for this address, `
				+ 'so we could not read it.';
	}
}

/**
 * The terms the Exchange resolved, in the shape the controls hold them.
 *
 * When a site publishes an rsl.txt the service reads its terms and builds the
 * offer from them, so the controls open on what the publisher already states
 * rather than on a default they never chose. Returns null when the offer
 * carries no term to read.
 */
export function resolvedControls(offer, offeredUses) {
	const term = Array.isArray(offer?.terms) ? offer.terms[0] : null;
	if (!term || typeof term !== 'object') return null;

	const restrictions = Array.isArray(term.restrictions) ? term.restrictions : [];
	const functions = restrictions.find((r) => r?.kind === 'RESTRICTION_KIND_FUNCTION') ?? restrictions[0] ?? {};
	const permitted = new Set(Array.isArray(functions.permitted) ? functions.permitted : []);

	const pricing = term.pricing ?? offer.pricing ?? {};
	const paid = pricing.model && pricing.model !== 'PRICING_MODEL_FREE';

	return {
		pricingModel: paid ? 'per_unit' : 'free',
		rate: paid && pricing.rate ? String(pricing.rate) : '',
		permittedFunctions: offeredUses.filter((token) => permitted.has(token)),
		attributionRequired: (Array.isArray(term.obligations) ? term.obligations : [])
			.some((o) => o?.kind === 'OBLIGATION_KIND_ATTRIBUTION'),
	};
}

/**
 * Turn an offer into an outline.
 *
 * Returns { nodes }, where every node is { label, value } or
 * { label, children }. The caller decides how an indent looks.
 */
export function offerOutline(offer) {
	const safe = offer && typeof offer === 'object' ? offer : {};
	const nodes = fieldNodes(safe, OFFER_ORDER, offerField);
	// Terms are what the offer is for, so the line stands even when the Exchange
	// sent none -- their absence is the thing a reader needs to see.
	if (!nodes.some((node) => node.label === label('terms'))) {
		nodes.push({ label: label('terms'), value: 'none stated' });
	}
	return { nodes };
}

/** Walk an object's fields in a preferred order, then whatever else it carries. */
function fieldNodes(source, order, render) {
	const seen = new Set();
	const nodes = [];
	const push = (key) => {
		if (seen.has(key)) return;
		seen.add(key);
		if (!hasValue(source[key])) return;
		const node = render(key, source[key], source);
		if (node) nodes.push(node);
	};
	for (const key of order) push(key);
	for (const key of Object.keys(source)) push(key);
	return nodes;
}

/** How one of the offer's own fields renders. */
function offerField(key, value) {
	if (key === 'pricing') return { label: label(key), value: priceSentence(value) };
	if (key === 'terms') return termsNode(value);
	if (key === 'previews') return listNode(key, value, (p) => [p.media_type, p.size, p.url].filter(Boolean).join(' · '));
	if (key === 'subscription_quota') return listNode(key, value, quotaSentence);
	if (key === 'attestations') return listNode(key, value, (a) => a?.level ? enumLabel(a.level) : summarise(a));
	return generic(key, value);
}

/** How one of a term's fields renders. */
function termField(key, value, term) {
	if (key === 'restrictions') return { label: label(key), value: conditionSentence(term) };
	if (key === 'pricing') return { label: label(key), value: priceSentence(value) };
	if (key === 'obligations') return listNode(key, value, obligationSentence);
	if (key === 'quotas') return listNode(key, value, quotaSentence);
	return generic(key, value);
}

function termsNode(terms) {
	const list = Array.isArray(terms) ? terms : [];
	if (list.length === 0) return { label: label('terms'), value: 'none stated' };
	if (list.length === 1) return { label: label('terms'), children: fieldNodes(list[0], TERM_ORDER, termField) };
	return {
		label: label('terms'),
		children: list.map((term, i) => ({
			label: `term ${i + 1}`,
			children: fieldNodes(term, TERM_ORDER, termField),
		})),
	};
}

/**
 * A repeated field. One entry becomes one line under the field's label, so the
 * reader sees each obligation or quota on its own rather than as a blob.
 */
function listNode(key, entries, toLine) {
	const list = (Array.isArray(entries) ? entries : []).map(toLine).filter((line) => line !== '');
	if (list.length === 0) return null;
	if (list.length === 1) return { label: label(key), value: list[0] };
	return { label: label(key), children: list.map((line) => ({ value: line })) };
}

/** Anything without its own treatment: a scalar, a list of scalars, or an object. */
function generic(key, value) {
	if (Array.isArray(value)) {
		if (value.every((entry) => entry === null || typeof entry !== 'object')) {
			return { label: label(key), value: sentenceList(value.map(String)) };
		}
		return { label: label(key), children: value.map((entry) => ({ children: fieldNodes(entry, [], generic) })) };
	}
	if (value && typeof value === 'object') {
		return { label: label(key), children: fieldNodes(value, [], generic) };
	}
	return { label: label(key), value: scalar(key, value) };
}

function scalar(key, value) {
	if (typeof value === 'boolean') return value ? 'yes' : 'no';
	if (ABBREVIATED.has(key)) return abbreviate(value);
	if (key.endsWith('_at') || key === 'data_as_of') return timeLabel(value);
	if (typeof value === 'string' && isEnumValue(value)) return enumLabel(value);
	return String(value);
}

function summarise(value) {
	if (value === null || typeof value !== 'object') return String(value ?? '');
	const first = Object.values(value).find((entry) => entry !== null && typeof entry !== 'object');
	return first === undefined ? '' : String(first);
}

function label(key) {
	return FIELD_LABELS[key] ?? humanise(key).toLowerCase();
}

function hasValue(value) {
	if (value === null || value === undefined || value === '') return false;
	if (Array.isArray(value)) return value.length > 0;
	if (typeof value === 'object') return Object.keys(value).length > 0;
	return true;
}
