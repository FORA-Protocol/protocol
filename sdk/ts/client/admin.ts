// The operator's client: fora.admin.v1.AdminService and the two domain-verification RPCs.
//
// AdminService carries Exchange operator overrides — a tenant's fee rate and reporting
// policy — and the contract keeps it off the agent-facing listener: deployments restrict
// it at the network layer, and it carries no RFC 9421 signing requirement. Domain
// verification is ExchangeService (RequestDomainVerification, then
// ConfirmDomainVerification once the challenge token is served), and it is the operator
// or provider tooling that drives it, so it sits on this face rather than the agent's.
//
// Every call goes to the configured base URL over the plain send: the operator chose the
// address. A deployment that serves the admin listener and the Exchange endpoint apart
// builds one client per address. A configured signer signs every call; without one the
// calls go unsigned, which is what the admin plane expects.

import type { z } from "zod";

import {
	DomainVerificationChallengeSchema,
	DomainVerificationConfirmationSchema,
	DomainVerificationRequestSchema,
	DomainVerificationResultSchema,
	SetReportingPolicyRequestSchema,
	SetReportingPolicyResponseSchema,
	SetTenantFeeRateRequestSchema,
	SetTenantFeeRateResponseSchema,
} from "../../../gen/ts/wire/schemas.ts";
import { call, resolve, type ClientOptions, type Resolved } from "./options.ts";
import { RawBody } from "./raw.ts";
import { requireRecipient, stampVer, stringField } from "./stamp.ts";
import { parseMessage, validateRequest } from "./transport.ts";

const ADMIN_SERVICE = "fora.admin.v1.AdminService";
const EXCHANGE_SERVICE = "fora.v1.ExchangeService";

export type SetTenantFeeRateRequest = z.input<typeof SetTenantFeeRateRequestSchema>;
export type SetTenantFeeRateResponse = z.infer<typeof SetTenantFeeRateResponseSchema>;
export type SetReportingPolicyRequest = z.input<typeof SetReportingPolicyRequestSchema>;
export type SetReportingPolicyResponse = z.infer<typeof SetReportingPolicyResponseSchema>;
export type DomainVerificationRequest = z.input<typeof DomainVerificationRequestSchema>;
export type DomainVerificationChallenge = z.infer<typeof DomainVerificationChallengeSchema>;
export type DomainVerificationConfirmation = z.input<typeof DomainVerificationConfirmationSchema>;
export type DomainVerificationResult = z.infer<typeof DomainVerificationResultSchema>;

type Request<T> = T | Record<string, unknown> | RawBody;

/** The operator-facing client. */
export interface AdminClient {
	/** Set a tenant's fee rate (AdminService.SetTenantFeeRate). Full replace. */
	setTenantFeeRate(request: Request<SetTenantFeeRateRequest>): Promise<SetTenantFeeRateResponse>;
	/** Replace a tenant's reporting policy (AdminService.SetReportingPolicy). */
	setReportingPolicy(
		request: Request<SetReportingPolicyRequest>,
	): Promise<SetReportingPolicyResponse>;
	/** Ask the Exchange for a domain-verification challenge
	 * (ExchangeService.RequestDomainVerification). */
	requestDomainVerification(
		request: Request<DomainVerificationRequest>,
	): Promise<DomainVerificationChallenge>;
	/** Confirm the challenge is served and optionally register a signing key
	 * (ExchangeService.ConfirmDomainVerification). */
	confirmDomainVerification(
		request: Request<DomainVerificationConfirmation>,
	): Promise<DomainVerificationResult>;
}

type Schema = { safeParse: (v: unknown) => { success: boolean; data?: unknown } };

/** One admin-face verb. */
interface AdminVerb {
	op: string;
	service: string;
	method: string;
	request: Schema;
	response: Schema;
	/** The fully-qualified response message, which strict decoding validates. */
	responseName: string;
	/** Whether the message names its recipient, which is then required. */
	addressed: boolean;
}

const SET_TENANT_FEE_RATE: AdminVerb = {
	op: "set tenant fee rate",
	service: ADMIN_SERVICE,
	method: "SetTenantFeeRate",
	request: SetTenantFeeRateRequestSchema,
	response: SetTenantFeeRateResponseSchema,
	responseName: "fora.admin.v1.SetTenantFeeRateResponse",
	addressed: false,
};
const SET_REPORTING_POLICY: AdminVerb = {
	op: "set reporting policy",
	service: ADMIN_SERVICE,
	method: "SetReportingPolicy",
	request: SetReportingPolicyRequestSchema,
	response: SetReportingPolicyResponseSchema,
	responseName: "fora.admin.v1.SetReportingPolicyResponse",
	addressed: false,
};
const REQUEST_DOMAIN_VERIFICATION: AdminVerb = {
	op: "request domain verification",
	service: EXCHANGE_SERVICE,
	method: "RequestDomainVerification",
	request: DomainVerificationRequestSchema,
	response: DomainVerificationChallengeSchema,
	responseName: "fora.v1.DomainVerificationChallenge",
	addressed: true,
};
const CONFIRM_DOMAIN_VERIFICATION: AdminVerb = {
	op: "confirm domain verification",
	service: EXCHANGE_SERVICE,
	method: "ConfirmDomainVerification",
	request: DomainVerificationConfirmationSchema,
	response: DomainVerificationResultSchema,
	responseName: "fora.v1.DomainVerificationResult",
	addressed: true,
};

/**
 * createAdminClient builds the operator client against baseURL. It takes the same options
 * as every other face; the agent-only ones are inert here.
 *
 * Each call fills `ver` when the caller left it empty and checks the request against its
 * generated schema (unless `validation: "off"`). The two domain-verification requests name
 * their recipient in `exchange`, so a request naming none, or naming something that is not
 * a bare domain, is refused as `not_sent` before anything is signed. A RawBody is sent as
 * given, and strict decoding applies to every answer.
 */
export function createAdminClient(baseURL: string, options: ClientOptions = {}): AdminClient {
	const r = resolve(options);
	return {
		setTenantFeeRate: (request) => adminCall(r, baseURL, SET_TENANT_FEE_RATE, request),
		setReportingPolicy: (request) => adminCall(r, baseURL, SET_REPORTING_POLICY, request),
		requestDomainVerification: (request) =>
			adminCall(r, baseURL, REQUEST_DOMAIN_VERIFICATION, request),
		confirmDomainVerification: (request) =>
			adminCall(r, baseURL, CONFIRM_DOMAIN_VERIFICATION, request),
	};
}

async function adminCall<T>(
	r: Resolved,
	baseURL: string,
	verb: AdminVerb,
	request: Record<string, unknown> | RawBody,
): Promise<T> {
	let message: unknown = request;
	if (!(request instanceof RawBody)) {
		const sent = stampVer(verb.op, request);
		if (verb.addressed) requireRecipient(verb.op, stringField(sent, "exchange"));
		validateRequest(verb.op, sent, verb.request, r.opts.validation ?? "strict");
		message = sent;
	}
	const raw = await call(
		r,
		verb.op,
		baseURL,
		verb.service,
		verb.method,
		message,
		false,
		verb.responseName,
	);
	return parseMessage<T>(verb.op, raw, verb.response);
}
