package helpers_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

type discoveryHintCorpus struct {
	HeaderNames map[string]string `json:"header_names"`
	Parse       []struct {
		Name     string      `json:"name"`
		Status   int         `json:"status"`
		Headers  [][2]string `json:"headers"`
		Expected struct {
			ContentRules      string `json:"content_rules"`
			ContentRulesState string `json:"content_rules_state"`
			Exchange          string `json:"exchange"`
			ExchangeState     string `json:"exchange_state"`
		} `json:"expected"`
	} `json:"parse"`
	Reconcile []struct {
		Name      string      `json:"name"`
		Status    int         `json:"status"`
		Headers   [][2]string `json:"headers"`
		Listed    []string    `json:"listed"`
		Agreement string      `json:"expected_agreement"`
	} `json:"reconcile"`
}

func loadDiscoveryHintCorpus(t *testing.T) discoveryHintCorpus {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "discovery-hint-vectors.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c discoveryHintCorpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	if len(c.Parse) == 0 || len(c.Reconcile) == 0 {
		t.Fatal("discovery-hint corpus has an empty section")
	}
	return c
}

// responseHeader builds the header the way a caller holds it: it writes a raw
// HTTP/1.1 response carrying the pairs and reads it back with
// http.ReadResponse, so the replay covers net/http's own name canonicalisation
// and value trimming rather than a header assembled by hand.
func responseHeader(t *testing.T, status int, pairs [][2]string) http.Header {
	t.Helper()
	var raw strings.Builder
	fmt.Fprintf(&raw, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for _, p := range pairs {
		fmt.Fprintf(&raw, "%s: %s\r\n", p[0], p[1])
	}
	raw.WriteString("Content-Length: 0\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw.String())), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d", resp.StatusCode, status)
	}
	return resp.Header
}

// TestDiscoveryHint_ReplaysCommittedCorpus reads the committed file back, the
// way the Python and TypeScript suites do, so a corpus edited by hand fails
// here as well as in the emitter's drift check.
func TestDiscoveryHint_ReplaysCommittedCorpus(t *testing.T) {
	c := loadDiscoveryHintCorpus(t)
	if c.HeaderNames["content_rules"] != helpers.ContentRulesHeader || c.HeaderNames["exchange"] != helpers.ExchangeHeader {
		t.Fatalf("corpus header names %v differ from the constants", c.HeaderNames)
	}
	for _, v := range c.Parse {
		got := helpers.ParseDiscoveryHint(v.Status, responseHeader(t, v.Status, v.Headers))
		if got.ContentRules != v.Expected.ContentRules || got.ContentRulesState.String() != v.Expected.ContentRulesState ||
			got.Exchange != v.Expected.Exchange || got.ExchangeState.String() != v.Expected.ExchangeState {
			t.Errorf("%s: got %+v, corpus says %+v", v.Name, got, v.Expected)
		}
	}
	for _, v := range c.Reconcile {
		hint := helpers.ParseDiscoveryHint(v.Status, responseHeader(t, v.Status, v.Headers))
		if got := helpers.ReconcileDiscoveryHint(hint, v.Listed).String(); got != v.Agreement {
			t.Errorf("%s: got %s, corpus says %s", v.Name, got, v.Agreement)
		}
	}
}

// TestDiscoveryHint_ZeroValueIsNothingToActOn pins the zero values: a hint
// nobody filled in reads as both headers absent and no Exchange to reconcile,
// never as a valid or listed one.
func TestDiscoveryHint_ZeroValueIsNothingToActOn(t *testing.T) {
	var hint helpers.DiscoveryHint
	if hint.ContentRulesState != helpers.HintAbsent || hint.ExchangeState != helpers.HintAbsent {
		t.Fatalf("zero DiscoveryHint states = %s/%s, want absent", hint.ContentRulesState, hint.ExchangeState)
	}
	if got := helpers.ReconcileDiscoveryHint(hint, []string{"exchange.example"}); got != helpers.HintNoExchange {
		t.Fatalf("zero hint reconciles to %s, want no_exchange", got)
	}
}

// TestDiscoveryHint_NilHeaderIsAbsent covers a 403 with no header map at all.
func TestDiscoveryHint_NilHeaderIsAbsent(t *testing.T) {
	got := helpers.ParseDiscoveryHint(http.StatusForbidden, nil)
	if got != (helpers.DiscoveryHint{}) {
		t.Fatalf("nil header parsed to %+v, want the zero hint", got)
	}
}

func TestDiscoveryHint_UnknownTokens(t *testing.T) {
	if s := helpers.HintState(9).String(); s != "HintState(9)" {
		t.Fatalf("HintState(9) = %q", s)
	}
	if s := helpers.HintAgreement(9).String(); s != "HintAgreement(9)" {
		t.Fatalf("HintAgreement(9) = %q", s)
	}
}
