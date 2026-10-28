package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocDelegationClaimGuard(t *testing.T) {
	script, err := os.ReadFile("../scripts/check-doc-conformance.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, claims, refusal string
	}{
		{"jwt_only", "fora_parent fora_advisory", ""},
		{"mirror", "fora_max_spend_cents", ""},
		{"unknown", "fora_parnet", "registered delegation claim 'fora_parnet' has no matching"},
		{"other_message_field", "fora_offer_id", "registered delegation claim 'fora_offer_id' has no matching"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for path, content := range map[string]string{
				"scripts/check-doc-conformance.sh": string(script),
				"proto/fora/v1/fora.proto": "message Delegation {\n  int64 max_spend_cents = 1;\n}\n" +
					"message TransactionItem {\n  string offer_id = 1;\n}\n",
				"website/src/content/docs/protocol/authentication.mdx":                tc.claims,
				"website/src/content/docs/components/transaction-log/event-types.mdx": "",
				"docs/placeholder.md": "",
			} {
				target := filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
			}
			out, err := exec.Command("bash", filepath.Join(root, "scripts/check-doc-conformance.sh")).CombinedOutput()
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("valid claim rejected: %v\n%s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), tc.refusal) {
				t.Fatalf("expected refusal %q, got %v\n%s", tc.refusal, err, out)
			}
		})
	}
}
