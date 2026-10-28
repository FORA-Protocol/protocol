package conformance

import (
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocHandlerExampleCompiles pins the DiscoverResources handler example of
// the Exchange request-flows page to conformance/docgo/requestflows/handler.go,
// a package that compiles the example against typed stubs. The page is the
// source: under FORA_UPDATE_VECTORS=1 the file is rewritten from it, otherwise
// the two must match, and `go test ./...` compiles the package, so an example
// that uses a variable before declaring it or calls the SDK wrongly fails CI.
func TestDocHandlerExampleCompiles(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "website", "src", "content", "docs", "components", "exchange", "request-flows.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(page)
	i := strings.Index(content, "### Handler Implementation")
	if i < 0 {
		t.Fatal("request-flows.mdx has no Handler Implementation section")
	}
	content = content[i:]
	start := strings.Index(content, "```go\n")
	if start < 0 {
		t.Fatal("no Go fence under Handler Implementation")
	}
	content = content[start+len("```go\n"):]
	block := content[:strings.Index(content, "```")]

	path := filepath.Join("docgo", "requestflows", "handler.go")
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	preamble := string(existing)[:strings.Index(string(existing), "func (h *ExchangeHandler) DiscoverResources(")]
	formatted, err := format.Source([]byte(preamble + block))
	if err != nil {
		t.Fatalf("the example does not parse as Go: %v", err)
	}
	want := string(formatted)
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(existing) != want {
		t.Fatalf("%s differs from the example on the page; regenerate with FORA_UPDATE_VECTORS=1", path)
	}
}
