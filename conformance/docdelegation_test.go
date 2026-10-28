package conformance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// Documented delegation tokens must verify.
//
// A page that shows a delegation token shows a real one, taken from the shared
// chain cases (sdk/go/helpers/testdata/delegation-chains.json), and names the
// case on the line above the fence: {/* delegation-chain: <case name> */}. The
// fenced block is either a proto-JSON request whose requester.delegation.token
// carries the token base64-encoded, or the bare compact JWS. This test finds
// every such block, checks the token is byte-identical to the named case, and
// verifies it with helpers.VerifyDelegation under the case's trust input,
// audience, holder thumbprint and clock, expecting the case's declared outcome.
// A proto-JSON block that carries a real-looking token without a marker fails
// too, so no page can show a token nothing verifies.

var chainMarkedFenceRe = regexp.MustCompile("(?s)(?:\\{/\\* delegation-chain: ([a-z0-9_]+) \\*/\\}\\s*\\n)?(?:\\{/\\* fora-validate: [A-Za-z0-9]+ \\*/\\}\\s*\\n)?```[a-zA-Z0-9]*[ \t]*\\n(.*?)```")

type docChainCase struct {
	Name    string `json:"name"`
	Token   string `json:"token"`
	Trusted []struct {
		Identity string `json:"identity"`
		KeyX     string `json:"key_x"`
	} `json:"trusted"`
	Audience string `json:"audience"`
	Holder   string `json:"holder"`
	Now      string `json:"now"`
	Expect   struct {
		Valid     bool     `json:"valid"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	} `json:"expect"`
}

func loadDocChainCases(t *testing.T) map[string]docChainCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "sdk", "go", "helpers", "testdata", "delegation-chains.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []docChainCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]docChainCase{}
	for _, c := range doc.Cases {
		out[c.Name] = c
	}
	return out
}

// documentedToken returns the token a fenced block documents: the base64
// (standard or URL, padded or not) requester.delegation.token of a proto-JSON
// request, or the block itself when it is one bare compact JWS.
func documentedToken(body string) (token string, found bool) {
	trimmed := strings.TrimSpace(body)
	if strings.Count(trimmed, ".") == 2 && !strings.ContainsAny(trimmed, " \n{}") {
		return trimmed, true
	}
	var req struct {
		Requester struct {
			Delegation struct {
				Token string `json:"token"`
			} `json:"delegation"`
		} `json:"requester"`
	}
	if err := json.Unmarshal([]byte(trimmed), &req); err != nil || req.Requester.Delegation.Token == "" {
		return "", false
	}
	enc := req.Requester.Delegation.Token
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(enc); err == nil {
			return string(b), true
		}
	}
	return enc, true
}

func TestDocDelegationTokensVerify(t *testing.T) {
	cases := loadDocChainCases(t)
	verified := 0
	walkDocs(t, func(path, content string) {
		for _, m := range chainMarkedFenceRe.FindAllStringSubmatch(content, -1) {
			name, body := m[1], m[2]
			token, found := documentedToken(body)
			if !found {
				continue
			}
			if name == "" {
				if isPlaceholder(token) {
					continue
				}
				t.Errorf("%s: a documented delegation token has no {/* delegation-chain: <case> */} marker, so nothing verifies it", filepath.Base(path))
				continue
			}
			c, ok := cases[name]
			if !ok {
				t.Errorf("%s: delegation-chain %q is not a case in delegation-chains.json", filepath.Base(path), name)
				continue
			}
			if token != c.Token {
				t.Errorf("%s: the documented token differs from case %q", filepath.Base(path), name)
				continue
			}
			in := helpers.DelegationInput{Token: []byte(token), Audience: c.Audience, Holder: c.Holder}
			var err error
			if in.Now, err = time.Parse(time.RFC3339, c.Now); err != nil {
				t.Fatal(err)
			}
			for _, tr := range c.Trusted {
				x, err := base64.RawURLEncoding.DecodeString(tr.KeyX)
				if err != nil {
					t.Fatal(err)
				}
				in.TrustedIssuers = append(in.TrustedIssuers, helpers.TrustedIssuer{Identity: tr.Identity, Key: ed25519.PublicKey(x)})
			}
			got, err := helpers.VerifyDelegation(in)
			if !c.Expect.Valid {
				t.Errorf("%s: case %q is a refusal case; a page documents only chains that verify", filepath.Base(path), name)
				continue
			}
			if err != nil {
				t.Errorf("%s: documented token %q does not verify: %v", filepath.Base(path), name, err)
				continue
			}
			if strings.Join(got.Scopes, " ") != strings.Join(c.Expect.Scopes, " ") || got.ExpiresAt.UTC().Format(time.RFC3339) != c.Expect.ExpiresAt {
				t.Errorf("%s: documented token %q verified to %+v, case declares %+v", filepath.Base(path), name, got, c.Expect)
				continue
			}
			verified++
		}
	})
	if verified == 0 {
		t.Fatal("no documented delegation token was verified; the docs must show at least one real chain")
	}
	t.Logf("documented delegation tokens verified=%d", verified)
}
