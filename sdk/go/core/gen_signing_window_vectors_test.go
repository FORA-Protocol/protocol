package core_test

// Signing-window golden-vector emitter.
//
// A signature's lifetime is a cross-language contract: every signature a signing
// transport emits has expires - created equal to the window's TTL, created is the
// clock's current second and never ahead of it, and a TTL that is not positive or is
// longer than helpers.MaxSignatureLifetime is refused before anything is sent. That
// holds at any request rate. Each row of testdata/signing-window-vectors.json names a
// window kind, its TTL and a sequence of clock readings, one signed request per
// reading, and records what the real Go signing transport stamped on each request, or
// the refusal. Python and TypeScript replay every row through their own signing
// transport with the same injected clock. A "default" row is signed by a transport
// built with no window option: Go injects the clock with core.WithClock, Python with
// SigningTransport(now=...), and TypeScript moves Date.now with fake timers.
//
// Every expected value is DERIVED by sending the request through
// core.NewSigningTransport and reading created and expires back off the
// Signature-Input header the base transport received. checkSigningWindowVector then
// asserts the bound on what was derived, independently of the committed file, so a Go
// regression fails here rather than being written into the corpus.
//
// Verification no-op by default (it asserts the committed file matches a fresh emit);
// (re)writes under FORA_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

var signingWindowVectorsPath = filepath.Join("testdata", "signing-window-vectors.json")

// refusedSignatureLifetime is the corpus token for a window the signer refuses. Go
// returns helpers.ErrSignatureLifetime, Python raises SignatureLifetimeError and
// TypeScript throws a WebBotAuthError with reason "signature_lifetime".
const refusedSignatureLifetime = "signature_lifetime"

// windowExpectation is what one signed request carried: created and expires, or the
// refusal token when nothing was sent. ExpectedReason is written on every expectation,
// "" for a signed request, as in the other signing corpora that record a reason token.
type windowExpectation struct {
	Created        int64  `json:"created,omitempty"`
	Expires        int64  `json:"expires,omitempty"`
	ExpectedReason string `json:"expected_reason"`
}

// signingWindowVector is one row: a window kind ("clock", "monotonic", or "default",
// the window a transport built with no window option signs with), the TTL in seconds,
// the clock readings in unix milliseconds, and one expectation per reading.
type signingWindowVector struct {
	Name     string              `json:"name"`
	Window   string              `json:"window"`
	TTLSec   int64               `json:"ttl_sec"`
	ClockMS  []int64             `json:"clock_ms"`
	Expected []windowExpectation `json:"expected"`
}

// signingWindowScenario is a row before its expectations are derived.
type signingWindowScenario struct {
	name    string
	window  string
	ttlSec  int64
	clockMS []int64
}

const windowT0 = int64(1_700_000_000_000) // unix ms

// steady returns n readings starting at start, step milliseconds apart.
func steady(start, step int64, n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = start + int64(i)*step
	}
	return out
}

// repeat returns n copies of ms.
func repeat(ms int64, n int) []int64 { return steady(ms, 0, n) }

func concat(parts ...[]int64) []int64 {
	var out []int64
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The clock steps back 40 s in the middle of a same-second burst, then forward again.
var windowStepsBack = concat(repeat(windowT0, 20), repeat(windowT0-40_000, 5), []int64{windowT0 + 1_000})

// A hundred requests spread over one second, 10 ms apart: one created second.
var windowOneSecond = steady(windowT0, 10, 100)

// kindScenarios are the rows every injected window kind carries: bursts, a clock that
// steps back, and TTLs at, over and under the limit.
func kindScenarios(kind string) []signingWindowScenario {
	limit := int64(helpers.MaxSignatureLifetime.Seconds())
	return []signingWindowScenario{
		{kind + "_hundred_in_one_second", kind, 30, windowOneSecond},
		{kind + "_clock_steps_back", kind, 30, windowStepsBack},
		{kind + "_ttl_at_the_limit", kind, limit, repeat(windowT0, 50)},
		{kind + "_ttl_one_second_over_the_limit", kind, limit + 1, steady(windowT0, 1_000, 3)},
		{kind + "_ttl_zero", kind, 0, repeat(windowT0, 2)},
	}
}

func signingWindowScenarios() []signingWindowScenario {
	limit := int64(helpers.MaxSignatureLifetime.Seconds())
	out := []signingWindowScenario{
		// Ten requests per second for a minute through the window that used to grow:
		// the old one-second-per-request shift grew the last window of this row by
		// about nine minutes.
		{"monotonic_ten_per_second_for_a_minute", "monotonic", 30, steady(windowT0, 100, 600)},
		{"clock_ten_per_second_for_ten_seconds", "clock", 30, steady(windowT0, 100, 100)},
	}
	out = append(out, kindScenarios("monotonic")...)
	out = append(out, kindScenarios("clock")...)
	return append(out,
		signingWindowScenario{"default_hundred_in_one_second", "default", limit, windowOneSecond},
		signingWindowScenario{"default_clock_steps_back", "default", limit, windowStepsBack},
	)
}

// steppedClock is a test clock that the test moves by hand.
type steppedClock struct{ at time.Time }

func (c *steppedClock) now() time.Time { return c.at }

// windowOption returns the option that gives a row's transport its window over now. A
// "default" row gets no window, only the clock, so it signs through the window the
// transport builds for itself.
func windowOption(t *testing.T, kind string, now func() time.Time, ttlSec int64) core.SigningOption {
	t.Helper()
	ttl := time.Duration(ttlSec) * time.Second
	switch kind {
	case "clock":
		return core.WithWindow(core.ClockWindow(now, ttl))
	case "monotonic":
		return core.WithWindow(core.MonotonicWindow(now, ttl))
	case "default":
		if ttlSec != int64(helpers.MaxSignatureLifetime.Seconds()) {
			t.Fatalf("a default row records the default TTL, %v; got %ds", helpers.MaxSignatureLifetime, ttlSec)
		}
		return core.WithClock(now)
	}
	t.Fatalf("unknown window kind %q", kind)
	return nil
}

var createdExpiresRe = regexp.MustCompile(`;created=(\d+);expires=(\d+)`)

// signOnce sends one bodied request through tr and returns what the base transport
// saw: created and expires, or the refusal token when the transport refused and sent
// nothing.
func signOnce(t *testing.T, tr http.RoundTripper, base *captureTransport) windowExpectation {
	t.Helper()
	base.req = nil
	resp, err := tr.RoundTrip(bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources"))
	if err != nil {
		if !errors.Is(err, helpers.ErrSignatureLifetime) {
			t.Fatalf("RoundTrip: %v; want success or helpers.ErrSignatureLifetime", err)
		}
		if base.req != nil {
			t.Fatal("a refused signature still reached the base transport")
		}
		return windowExpectation{ExpectedReason: refusedSignatureLifetime}
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close the response body: %v", err)
	}
	m := createdExpiresRe.FindStringSubmatch(base.req.Header.Get("Signature-Input"))
	if m == nil {
		t.Fatalf("Signature-Input carries no created/expires pair: %q", base.req.Header.Get("Signature-Input"))
	}
	created, _ := strconv.ParseInt(m[1], 10, 64)
	expires, _ := strconv.ParseInt(m[2], 10, 64)
	return windowExpectation{Created: created, Expires: expires}
}

func buildSigningWindowVectors(t *testing.T) []signingWindowVector {
	t.Helper()
	signer := testSigner(t)
	out := make([]signingWindowVector, 0, len(signingWindowScenarios()))
	for _, s := range signingWindowScenarios() {
		clk := &steppedClock{}
		base := &captureTransport{}
		tr := core.NewSigningTransport(signer, base, core.WithSignatureAgent(testDir),
			windowOption(t, s.window, clk.now, s.ttlSec))
		v := signingWindowVector{Name: s.name, Window: s.window, TTLSec: s.ttlSec, ClockMS: s.clockMS}
		for _, ms := range s.clockMS {
			clk.at = time.UnixMilli(ms)
			v.Expected = append(v.Expected, signOnce(t, tr, base))
		}
		out = append(out, v)
	}
	return out
}

// checkSigningWindowVector asserts the bound on a derived row: a TTL in (0, limit]
// signs every request at the clock's second with a lifetime of exactly the TTL, and
// any other TTL refuses every request.
func checkSigningWindowVector(t *testing.T, v signingWindowVector) {
	t.Helper()
	limit := int64(helpers.MaxSignatureLifetime.Seconds())
	for i, got := range v.Expected {
		second := v.ClockMS[i] / 1000
		want := windowExpectation{Created: second, Expires: second + v.TTLSec}
		if v.TTLSec <= 0 || v.TTLSec > limit {
			want = windowExpectation{ExpectedReason: refusedSignatureLifetime}
		}
		if got != want {
			t.Errorf("%s request %d at %d ms: got %+v; want %+v", v.Name, i, v.ClockMS[i], got, want)
			return
		}
	}
}

// TestGenerateSigningWindowVectors emits the signing-window corpus. Verification
// no-op by default; (re)writes under FORA_UPDATE_VECTORS=1.
func TestGenerateSigningWindowVectors(t *testing.T) {
	vectors := buildSigningWindowVectors(t)
	for _, v := range vectors {
		checkSigningWindowVector(t, v)
	}
	if t.Failed() {
		return
	}
	doc := map[string]any{
		"note": "One signed request per clock reading, through the signing transport. " +
			"expires - created is the TTL and created is the clock's second, at any " +
			"request rate; a TTL that is not positive or exceeds " +
			"max_signature_lifetime_sec is refused and nothing is sent.",
		"max_signature_lifetime_sec": int64(helpers.MaxSignatureLifetime.Seconds()),
		"vectors":                    vectors,
	}
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(signingWindowVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", signingWindowVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(signingWindowVectorsPath, doc)
	if err != nil {
		t.Fatalf("read %s: %v", signingWindowVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", signingWindowVectorsPath)
	}
}

// TestSigningWindow_NoClockReadsTheRealClock covers the one default-path case the
// corpus cannot: a transport built with neither WithWindow nor WithClock reads
// time.Now. On that forward-moving clock it checks that every signature lives exactly
// helpers.MaxSignatureLifetime and is stamped within the clock's readings around it.
// A clock that steps back is covered by the corpus's default rows, which inject the
// clock with WithClock.
func TestSigningWindow_NoClockReadsTheRealClock(t *testing.T) {
	t.Parallel()
	base := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), base, core.WithSignatureAgent(testDir))
	limit := int64(helpers.MaxSignatureLifetime.Seconds())
	before := time.Now().Unix()
	for i := range 200 {
		got := signOnce(t, tr, base)
		if after := time.Now().Unix(); got.Expires-got.Created != limit || got.Created < before || got.Created > after {
			t.Fatalf("request %d: %+v; want a %ds lifetime created within [%d, %d]", i, got, limit, before, after)
		}
	}
}
