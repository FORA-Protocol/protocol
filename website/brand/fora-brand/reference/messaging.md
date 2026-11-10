# FORA naming and claims

Facts here are checked against fora-protocol.org as of November 2026. For
anything version- or date-sensitive, read the site's changelog
(<https://fora-protocol.org/reference/changelog/>) instead of trusting this file.

## What FORA is, in one line

FORA is an open transaction protocol that lets AI agents discover, license, pay
for and receive content on terms the rights holder sets, with every step signed.

Shorter: **Licensed content access for AI agents.**

## Facts you may state

- FORA stands for Federated Open Resource Access.
- The protocol specification and the reference implementation are open source
  under Apache 2.0. The documentation is CC BY-ND 4.0.
- SDKs exist for Go, TypeScript and Python. A hostable reference exchange is
  written in Go. Agents can also use FORA through an MCP server.
- The flow has six steps, named as on the site: **Discover, Query, Transact,
  Deliver, Report, Dispute.** Use these names; do not rename them.
  - Discover: the agent reads `/.well-known/fora.json` to find the Exchange.
  - Query: `DiscoverResources` returns signed offers with prices and terms.
  - Transact: `ExecuteTransaction` commits to one offer and returns a signed,
    time-limited delivery URL bound to the agent's identity.
  - Deliver: the agent fetches the content; a content hash lets it verify it.
  - Report: `ReportUsage` reports actual consumption.
  - Dispute: `DisputeTransaction` starts automated resolution.
- Offers are signed by the Exchange; requests and acceptances are signed by the
  agent. Signatures use Ed25519 and HTTP Message Signatures (RFC 9421); agent
  identity follows Web Bot Auth.
- FORA builds on existing open work: it ingests RSL, IAB Tech Lab's CoMP,
  TDMRep and C2PA. It is the transaction layer between them; it does not
  replace them.
- The protocol does not move money. An Exchange plugs in its own billing
  (Stripe, x402 or a custom adapter). The reference exchange runs a prepaid
  balance per agent.
- Anyone can run an Exchange. There is no central registry or gatekeeper.
- Licence terms can permit or prohibit specific uses. AI training (`ai-train`)
  is its own permission, separate from using content as input (`ai-input`);
  training is never implied by any other term.
- There is a public demo exchange and a demo music catalog (tracks under their own
  Creative Commons or public-domain licences). Demo purchases use test money and grant no real rights.

## Do not say

| Don't | Why | Say instead |
|---|---|---|
| "the FORA standard", "industry standard", "IAB standard" | No standards body has adopted it | "the open FORA protocol" |
| "FORA clears rights" / "guarantees compliance" / "no legal risk" | FORA carries the rights holder's terms and the signed acceptance; it does not grant rights or give legal cover | "agents buy on the rights holder's terms, and each purchase is signed and verifiable" |
| "FORA pays artists/publishers" | The protocol does not settle money; Exchanges and contracts do | "rights holders get paid through their Exchange" |
| "includes training rights", "licensed for AI" (unqualified) | Training is a separate, opt-in term | Name the permitted use exactly |
| Named customers, partners, pilots or deal terms | Only what fora-protocol.org lists is public | Leave them out, or ask the owner of the claim |
| Adoption, revenue or traffic numbers | None are published | Leave them out |
| Demo prices (€29 / €450 / €1,200) as real prices | They are demo examples | "demo prices, test money" |
| "replaces RSL / CoMP / TollBit", or knocking any of them | FORA builds on RSL and CoMP and can bridge marketplaces | "works with" / "builds on" |
| "blockchain", "crypto", "tokens" | FORA uses signatures, not a chain | "signed", "cryptographically verifiable" |
| "RAMP", "Fora", "F.O.R.A." | Old name, wrong spelling | "FORA" |

## Tone

Plain, specific, a little dry. Short sentences. Show the mechanism (what is
signed, by whom, what the agent receives) instead of adjectives. No hype words:
revolutionary, game-changing, seamless, unlock, empower, next-gen.

## Links to use

- Home: <https://fora-protocol.org>
- What is FORA: <https://fora-protocol.org/getting-started/what-is-fora/>
- Transaction flow: <https://fora-protocol.org/protocol/transaction-flow/>
- Music demo: <https://fora-protocol.org/getting-started/live-demo-music/>
- Code: <https://github.com/FORA-Protocol/protocol>

## Using the name and logo

The Apache 2.0 licence covers the code and spec, not the FORA name or logo.
You may use the name and logo to refer to FORA: articles, talks, diagrams,
"works with FORA" or "built on FORA" for software that implements the protocol.
Do not use them in your own product or company name, do not alter them, and do
not imply that the FORA project endorses, certifies or partners with you unless
it does in writing.
