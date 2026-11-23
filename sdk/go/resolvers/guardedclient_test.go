package resolvers_test

// The guarded client has no switch. SKIP_SSRF and ALLOW_INSECURE once turned its
// two checks off for a whole process; they are set here to prove nothing reads them
// any more. Every reserved address of the shared address corpus, and a plaintext
// URL, is refused by the guard, and a loopback listener standing in for the target
// records that no connection was made.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// retiredSwitches are the environment variables that used to relax the guard.
var retiredSwitches = []string{"SKIP_SSRF", "ALLOW_INSECURE"}

// countingListener accepts on a loopback port and counts the connections it sees.
func countingListener(t *testing.T) (port string, accepted *atomic.Int64) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted = &atomic.Int64{}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), accepted
}

// reservedAddresses returns the blocked rows of the shared address corpus that a URL
// can carry. A zoned literal (fe80::1%eth0) has no URL spelling the three SDKs'
// parsers share, so those rows stay with the predicate replay of the same corpus.
func reservedAddresses(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ssrf-address-vectors.json"))
	if err != nil {
		t.Fatalf("read the address corpus: %v", err)
	}
	var doc struct {
		Vectors []struct {
			Addr    string `json:"addr"`
			Blocked bool   `json:"blocked"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse the address corpus: %v", err)
	}
	var out []string
	for _, v := range doc.Vectors {
		if v.Blocked && !strings.Contains(v.Addr, "%") {
			out = append(out, v.Addr)
		}
	}
	if len(out) == 0 {
		t.Fatal("the address corpus has no reserved row a URL can carry; the replay would assert nothing")
	}
	return out
}

// getRefused asserts that GET url through client fails with the guard's refusal.
func getRefused(t *testing.T, client *http.Client, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("GET %s succeeded; the guard must refuse it", url)
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("GET %s failed for the wrong reason (want the SSRF guard): %v", url, err)
	}
}

func TestGuardedClient_TheRetiredSwitchesRelaxNothing(t *testing.T) {
	for _, name := range retiredSwitches {
		t.Setenv(name, "true")
	}
	port, accepted := countingListener(t)
	// The deprecated name returns the same client, so it is held to the same refusals.
	for _, client := range []*http.Client{resolvers.NewGuardedClient(), resolvers.NewGuardedClientFromEnv()} {
		for _, addr := range reservedAddresses(t) {
			getRefused(t, client, "https://"+net.JoinHostPort(addr, port)+"/")
		}
		getRefused(t, client, "http://127.0.0.1:"+port+"/")
		getRefused(t, client, "http://example.com/")
	}

	if n := accepted.Load(); n != 0 {
		t.Errorf("the loopback listener accepted %d connections; a refused target is never dialed", n)
	}
}
