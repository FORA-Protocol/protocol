package core_test

// A signature's lifetime under load, through the public signing surface.
//
// The bound: every signature the signing transport emits has expires - created
// equal to the window's TTL, and that TTL is at most helpers.MaxSignatureLifetime,
// whatever the request rate. created is the clock's current second, never ahead of
// it. Each test sends requests through core.NewSigningTransport with an injected
// clock and reads created and expires back off the Signature-Input header that the
// base transport received.

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

var createdExpiresRe = regexp.MustCompile(`;created=(\d+);expires=(\d+)`)

// signedWindow sends one bodied request through tr and returns the created and
// expires parameters on the Signature-Input header the base transport received.
func signedWindow(t *testing.T, tr http.RoundTripper, base *captureTransport) (created, expires int64) {
	t.Helper()
	base.req = nil
	if _, err := tr.RoundTrip(bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if base.req == nil {
		t.Fatal("the base transport received nothing")
	}
	m := createdExpiresRe.FindStringSubmatch(base.req.Header.Get("Signature-Input"))
	if m == nil {
		t.Fatalf("Signature-Input carries no created/expires pair: %q", base.req.Header.Get("Signature-Input"))
	}
	created, _ = strconv.ParseInt(m[1], 10, 64)
	expires, _ = strconv.ParseInt(m[2], 10, 64)
	return created, expires
}

// steppedClock is a test clock that the test moves by hand.
type steppedClock struct{ at time.Time }

func (c *steppedClock) now() time.Time { return c.at }

// TestSigningWindow_BurstAboveOnePerSecondKeepsTheTTL drives the deprecated
// MonotonicWindow, the window that used to grow with traffic, and ClockWindow at
// ten requests per second for one simulated minute, then a thousand requests in
// one frozen second. Each signature lives exactly the TTL and is stamped at the
// clock's second. The old one-second-per-request shift had grown the last window
// of the minute by about nine minutes.
func TestSigningWindow_BurstAboveOnePerSecondKeepsTheTTL(t *testing.T) {
	t.Parallel()
	const ttl = 30 * time.Second
	for name, mk := range map[string]func(func() time.Time, time.Duration) core.Window{
		"MonotonicWindow": core.MonotonicWindow,
		"ClockWindow":     core.ClockWindow,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			clk := &steppedClock{at: time.Unix(1_700_000_000, 0)}
			base := &captureTransport{}
			tr := core.NewSigningTransport(testSigner(t), base,
				core.WithSignatureAgent(testDir), core.WithWindow(mk(clk.now, ttl)))

			check := func(i int) {
				created, expires := signedWindow(t, tr, base)
				if life := expires - created; life != int64(ttl.Seconds()) {
					t.Fatalf("request %d: expires - created = %ds; want the TTL, %ds", i, life, int64(ttl.Seconds()))
				}
				if created != clk.at.Unix() {
					t.Fatalf("request %d: created = %d; want the clock's second %d", i, created, clk.at.Unix())
				}
			}
			for i := range 600 { // 10 rps for 60 s
				check(i)
				clk.at = clk.at.Add(100 * time.Millisecond)
			}
			for i := range 1000 { // 1000 requests inside one second
				check(600 + i)
			}
		})
	}
}

// TestSigningWindow_ClockGoingBackwards pins that the window follows a clock that
// steps back: created is the clock's new second, not a value held at the latest
// second seen, and the lifetime is still the TTL.
func TestSigningWindow_ClockGoingBackwards(t *testing.T) {
	t.Parallel()
	const ttl = 30 * time.Second
	clk := &steppedClock{at: time.Unix(1_700_000_100, 0)}
	base := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), base,
		core.WithSignatureAgent(testDir), core.WithWindow(core.MonotonicWindow(clk.now, ttl)))

	for range 50 {
		signedWindow(t, tr, base)
	}
	clk.at = clk.at.Add(-40 * time.Second)
	created, expires := signedWindow(t, tr, base)
	if created != 1_700_000_060 || expires != 1_700_000_090 {
		t.Fatalf("after the clock stepped back 40 s: (created, expires) = (%d, %d); want (1700000060, 1700000090)",
			created, expires)
	}
}

// TestSigningWindow_LifetimeLimit pins the edge of the bound: a window of exactly
// helpers.MaxSignatureLifetime signs, and one second more is refused with
// helpers.ErrSignatureLifetime before anything reaches the base transport.
func TestSigningWindow_LifetimeLimit(t *testing.T) {
	t.Parallel()
	clk := &steppedClock{at: time.Unix(1_700_000_000, 0)}

	t.Run("exactly the limit signs", func(t *testing.T) {
		t.Parallel()
		base := &captureTransport{}
		tr := core.NewSigningTransport(testSigner(t), base, core.WithSignatureAgent(testDir),
			core.WithWindow(core.MonotonicWindow(clk.now, helpers.MaxSignatureLifetime)))
		for range 100 {
			created, expires := signedWindow(t, tr, base)
			if life := expires - created; life != int64(helpers.MaxSignatureLifetime.Seconds()) {
				t.Fatalf("expires - created = %ds; want %ds", life, int64(helpers.MaxSignatureLifetime.Seconds()))
			}
		}
	})

	t.Run("one second over the limit sends nothing", func(t *testing.T) {
		t.Parallel()
		base := &captureTransport{}
		tr := core.NewSigningTransport(testSigner(t), base, core.WithSignatureAgent(testDir),
			core.WithWindow(core.ClockWindow(clk.now, helpers.MaxSignatureLifetime+time.Second)))
		_, err := tr.RoundTrip(bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources"))
		if !errors.Is(err, helpers.ErrSignatureLifetime) {
			t.Fatalf("RoundTrip err = %v; want helpers.ErrSignatureLifetime", err)
		}
		if base.req != nil {
			t.Fatal("a refused signature still reached the base transport")
		}
	})
}

// TestSigningWindow_DefaultWindowUnderBurst pins the transport's default window,
// read from the real clock: a tight burst signs every request with a lifetime of
// exactly helpers.MaxSignatureLifetime, and created stays within the clock's
// readings around the burst.
func TestSigningWindow_DefaultWindowUnderBurst(t *testing.T) {
	t.Parallel()
	base := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), base, core.WithSignatureAgent(testDir))
	before := time.Now().Unix()
	for i := range 500 {
		created, expires := signedWindow(t, tr, base)
		if life := expires - created; life != int64(helpers.MaxSignatureLifetime.Seconds()) {
			t.Fatalf("request %d: expires - created = %ds; want %ds", i, life, int64(helpers.MaxSignatureLifetime.Seconds()))
		}
		if after := time.Now().Unix(); created < before || created > after {
			t.Fatalf("request %d: created = %d, outside the clock's readings [%d, %d]", i, created, before, after)
		}
	}
}
