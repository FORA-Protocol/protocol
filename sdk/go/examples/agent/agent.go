// Command agent is the worked Go agent example the documentation site shows.
//
// The site does not keep its own copy of this code. Every Go block on the agent-SDK
// pages is a REGION of this file, pulled in at build time by
// website/plugins/remark-example.mjs, so what a reader copies is what the compiler
// checked. Four hand-kept copies of this flow lived on the site before, and they had
// already drifted: one of them called len() on a struct and would not build.
//
// Regions are delimited by "fora:example <name>" / "fora:/example <name>" comments.
// The marker lines never reach the page. Renaming or deleting a region fails the
// website build with the page and region named, so a region cannot be removed while a
// page still asks for it.
//
// This file is built by `go build ./...`, which is step 5 of scripts/ci-local.sh. That
// is the whole point: the gate that compiles the SDK compiles its documentation too.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"

	// fora:example imports
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/vocab/functiontokens"
	"github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
	// fora:/example imports
)

// buy fetches one URL through the four shipped verbs and reports what it used.
//
// The identity arguments are what a real agent holds: its request signer, the public
// half of the key a bound delivery fetch presents, who it says it is, and the key the
// Exchange signs offers with. They are parameters rather than globals because the SDK
// takes every one of them as an injected seam.
func buy(
	ctx context.Context,
	baseURL string,
	signer helpers.Signer,
	agentPublic ed25519.PublicKey,
	requester *forav1.Requester,
	exchangePublic ed25519.PublicKey,
) error {
	// fora:example client
	// The endpoint an Exchange serves comes from its own /.well-known/fora.json,
	// never from configuration; the same resolver routes usage reports back to
	// whichever Exchange issued the offer.
	endpoints := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{})

	client := connect.NewClient(baseURL,
		connect.WithSigner(signer),           // RFC 9421 request signing; custody stays yours
		connect.WithAgentKey(agentPublic),    // the public half a bound delivery fetch presents
		connect.WithRequester(requester),     // who this agent says it is
		connect.WithOfferKey(exchangePublic), // the key this Exchange signs offers with
		connect.WithEndpointResolver(endpoints),
	)
	// fora:/example client

	// fora:example discover
	// 1. Discover. Offers arrive already sorted into verified and rejected, and a
	//    rejected one keeps the reason it was refused.
	found, err := client.Discover(ctx, &forav1.ResourceQuery{
		Exchange: "exchange.example",
		Uris:     []string{"https://publisher.example/article"},
		// Which domains you work in is a property of the query rather than of the
		// client, so it goes here.
		SupportedProfiles: []string{
			"fora-news-v1",     // articles, podcasts, broadcasting
			"fora-academic-v1", // journal papers, preprints, datasets
			"fora-legal-v1",    // legislation, case law, patents
		},
	})
	if err != nil {
		return err
	}
	offers := found.Verified()
	if len(offers) == 0 {
		return fmt.Errorf("no verifiable offer: %v", found.Rejected())
	}
	// fora:/example discover

	// fora:example execute
	// 2. Buy. Execute accepts only a verified offer, so an unverified one cannot be
	//    paid for by mistake.
	tx, err := client.Execute(ctx, offers[0])
	if err != nil {
		return err
	}
	item := tx.GetItems()[0]
	// fora:/example execute

	// fora:example fetch
	// 3. Fetch. The delivery URL is bound to the agent's key and the client presents
	//    the matching proof of possession, so a copied link fetches nothing.
	content, err := client.Fetch(ctx, item.GetRetrievalEndpoint())
	if err != nil {
		return err
	}
	// fora:/example fetch

	// fora:example report
	// 4. Report what was used. ConsumedQuantity is the billed quantity, so a report
	//    without it bills nothing. Content.Body holds the fetched bytes, and function
	//    tokens come from the generated vocabulary rather than a string literal.
	resp, err := client.ReportUsage(ctx, &forav1.UsageReport{
		Exchange:      "exchange.example", // the Exchange that issued the offer
		TransactionId: item.GetTransactionId(),
		BillingId:     item.GetBillingId(),
		Usage: &forav1.Usage{
			ConsumedQuantity: int32(len(content.Body)),
			Function:         []string{functiontokens.AiInput},
		},
	})
	if err != nil {
		return err
	}
	// resp.GetReportId() is what a later dispute references.
	// fora:/example report

	// The example function has nothing further to do with the response; the block
	// above is what a caller sees, and this keeps the compiler satisfied without
	// putting a discard on the page.
	_ = resp

	return nil
}

func main() {
	// An example binary has no identity of its own to run with; buy is what the
	// documentation shows, and the compiler is what checks it.
	log.Println("compile-checked documentation example; see website/src/content/docs/components/agent-sdk/")
	_ = buy
}
