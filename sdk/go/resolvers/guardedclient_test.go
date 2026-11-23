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

// reservedAddresses returns every blocked row of the shared address corpus.
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
		if v.Blocked {
			out = append(out, v.Addr)
		}
	}
	if len(out) == 0 {
		t.Fatal("the address corpus has no reserved row; the replay would assert nothing")
	}
	return out
}

// reservedURL is the https URL of addr on port. An IPv6 literal is bracketed, and a
// zone in it is written the RFC 6874 way, its "%" escaped as "%25".
func reservedURL(addr, port string) string {
	if strings.Contains(addr, ":") {
		addr = "[" + strings.ReplaceAll(addr, "%", "%25") + "]"
	}
	return "https://" + addr + ":" + port + "/"
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
			getRefused(t, client, reservedURL(addr, port))
		}
		getRefused(t, client, "http://127.0.0.1:"+port+"/")
		getRefused(t, client, "http://example.com/")
	}

	if n := accepted.Load(); n != 0 {
		t.Errorf("the loopback listener accepted %d connections; a refused target is never dialed", n)
	}
}

// TestGuardedClientNoProxyTunnel: a set HTTP(S)_PROXY does not take a dial around the
// address pin. The proxy is a loopback listener that counts connections. A guarded
// client that honoured the proxy would dial it, and the refusal would then name the
// proxy's address, so the test asserts both that the refusal names the target and
// that the proxy saw no connection.
func TestGuardedClientNoProxyTunnel(t *testing.T) {
	proxyPort, proxied := countingListener(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:"+proxyPort)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:"+proxyPort)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://10.0.0.1/", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := resolvers.NewGuardedClient().Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), `refusing to dial "10.0.0.1"`) {
		t.Errorf("refusal = %v, want it to name the target 10.0.0.1 and not the proxy", err)
	}
	if n := proxied.Load(); n != 0 {
		t.Errorf("the proxy accepted %d connections; the guarded client must not use it", n)
	}
}
