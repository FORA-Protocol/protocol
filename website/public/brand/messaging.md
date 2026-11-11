# FORA naming and claims

Facts here are checked against fora-protocol.org as of November 2026. For
anything version- or date-sensitive, read the site's changelog
(<https://fora-protocol.org/reference/changelog/>) instead of trusting this file.

## What FORA is

Lead with what it does for the owner of the content, then how.

**Headline (the home page):** Every AI agent is a customer. FORA is your
storefront.

**Under the headline:** People are starting to search, research and buy through
AI agents instead of websites. FORA lets any agent find your pages or tracks,
read your license, pay, and get a signed receipt. You decide every term.

**The outcome in one line:** FORA makes a website or a music catalog licensable
to AI agents, instantly. Set your terms once, and FORA turns every page or track
into a signed offer that any AI agent can find, buy and verify, with no deal to
negotiate per buyer.

**For engineers:** FORA is an open transaction protocol that lets AI agents
discover, license, pay for and receive content on terms the rights holder sets,
with every step signed.

Pick the line for the audience. Rights holders, publishers and labels get the
headline, or the outcome line where there is room for only one sentence. Developers and agent builders can get the protocol
line first.

### What "instantly" means

Use "instantly" only in this sense: once a site or catalog is connected, every
page or track is on sale to every compatible agent at once, on the owner's
terms, with no negotiation or integration per buyer. It does not mean zero
setup. Do not promise "in minutes", "one click" or any other time.

The one-time setup, as the site describes it:

- **A website** registers on the publisher console, chooses its terms (price;
  search, AI input and AI training uses; attribution), serves one file
  (`/.well-known/fora.json`) and installs one package on its CDN (Cloudflare or
  AWS CloudFront). No CMS changes. Readers are unaffected. The operator imports
  the pages from the sitemap.
- **A music catalog** describes its tracks, its license documents and the
  licenses it sells, with prices, in one feed (JSON Lines, one track per line,
  search fields from the `fora-music-v1` profile) and pushes it to an Exchange.
  Delivery runs from its own domain and CDN, set up once. The demo catalog
  wrote no code to do this.
- **A marketplace that already exists** keeps its catalog, search and delivery.
  It publishes the catalog as a feed, and its customers reach it through the
  FORA SDKs and MCP endpoint.

### What the owner gets

Name these five, in this order, when you need the detail:

1. **Search.** Agents find the content by what it is about (for music: genre,
   mood, tempo and the other `music.*` fields).
2. **Terms an agent can read.** Each license becomes a signed offer with the
   price and the main terms; the full license text is at a public URL.
3. **Payment.** The Exchange checks the offer, charges the agent's account and
   records the transaction.
4. **Delivery.** The agent gets a short-lived signed link; the CDN checks it
   before serving the file.
5. **Evidence.** Each purchase leaves signed records anyone can check later.

### Taglines

- Every AI agent is a customer. *FORA is your storefront.*
- One storefront. Every agent.
- Make your website or music catalog licensable. *Instantly.*
- Free is a price too. (Charging nothing still carries your terms: attribution,
  permitted uses, no AI training unless offered.)
- Licensed content access for AI agents. (The older line. Still true; use it
  where the reader is an agent builder.)

## Facts you may state

- FORA stands for Federated Open Resource Access.
- The protocol specification and the reference implementation are open source
  under Apache 2.0. The documentation is CC BY-ND 4.0.
- SDKs exist for Go, TypeScript and Python. Agents can also use FORA through an
  MCP server.
- **FORA Server** is the reference implementation, written in Go. Call it FORA
  Server, not "the reference app" or "a sample": it is a working stack
  (exchange, broker and search, identity and registration, content ingestion,
  an MCP endpoint and edge protection). An owner can run all of it or one piece.
  The protocol and FORA Server are free and open source. An owner who does not
  want to run it can have it hosted: the operator of the publisher console runs
  the Exchange and the edge setup for them
  (<https://fora-protocol.org/getting-started/publisher-onboarding/>).
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
- License terms can permit or prohibit specific uses. AI training (`ai-train`)
  is its own permission, separate from using content as input (`ai-input`);
  training is never implied by any other term.
- Two live demos run on a public demo exchange, and anyone can try them today:
  the publisher demo (an agent licenses an article) and the music demo (an agent
  licenses a track from a demo catalog of tracks under their own Creative Commons
  or public-domain licenses). Both are fully connected marketplaces. Demo
  purchases use test money and grant no real rights.
- For music, FORA builds on the identifiers and vocabularies the industry already
  uses: DDEX (ERN and MEAD), ISRC, ISWC, IPI, ISNI, GRid and UPC/EAN. Name these,
  not IAB Tech Lab, when the reader is in music.

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
| "set up in minutes", "one click", "no setup" | Setup is one-time but real: a file and a CDN package, or a feed | "licensable instantly once connected", then name the setup |
| "stop AI scrapers", "block bots" as the promise | FORA sells access; blocking is a side effect of the edge package | "agents are pointed to your offer, not just turned away" |
| "Every AI agent is a storefront", "be on the agent's shelf" | In FORA the agent is the buyer: it reads the offer, pays and gets the receipt. Casting it as the store makes it the middleman FORA removes | "Every AI agent is a customer. FORA is your storefront." |
| "FORA brings you buyers" | FORA makes the content findable and buyable; it does not market it | "when an agent comes looking, it can find you, read your terms and pay" |
| "walled gardens" about other marketplaces | Knocks people FORA works with | "a deal per buyer" / "one offer for every agent" |
| "RAMP", "Fora", "F.O.R.A." | Old name, wrong spelling | "FORA" |

## Tone

Plain, specific, a little dry. Short sentences. Show the mechanism (what is
signed, by whom, what the agent receives) instead of adjectives. No hype words:
revolutionary, game-changing, seamless, unlock, empower, next-gen.

US English, as on fora-protocol.org: "license", "color", "catalog".

## Links to use

- Home: <https://fora-protocol.org>
- What is FORA: <https://fora-protocol.org/getting-started/what-is-fora/>
- Transaction flow: <https://fora-protocol.org/protocol/transaction-flow/>
- Music demo: <https://fora-protocol.org/getting-started/live-demo-music/>
- Check a website: <https://fora-protocol.org/publishers/onboarding/>
- Publisher onboarding: <https://fora-protocol.org/getting-started/publisher-onboarding/>
- For marketplaces: <https://fora-protocol.org/getting-started/existing-marketplace/>
- Code: <https://github.com/FORA-Protocol/protocol>

## Using the name and logo

The Apache 2.0 license covers the code and spec, not the FORA name or logo.
You may use the name and logo to refer to FORA: articles, talks, diagrams,
"works with FORA" or "built on FORA" for software that implements the protocol.
Do not use them in your own product or company name, do not alter them, and do
not imply that the FORA project endorses, certifies or partners with you unless
it does in writing.
