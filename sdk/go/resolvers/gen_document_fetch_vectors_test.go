package resolvers

// Golden-vector emitter for the document-fetch corpus.
//
// Every document read ends in one decision about the status it was answered with,
// made once per language in the shared GET: a 200 is read, a 404 is a missing
// document on every read, any 3xx is a refused redirect on a key-directory read, and
// anything else is an unavailable document. That decision is where three languages
// could disagree about the same answer: Go's client consults its redirect hook only
// for a followable status carrying a Location, while the other two SDKs see every
// 3xx. This corpus makes the three answer the same statuses with the same verdict.
//
// document-fetch-vectors.json: {name, read, status, location, verdict}. read is
// "key_directory" (a read that refuses every redirect) or "document" (one that may
// follow them); location "" means the answer carries none; verdict is one of
//
//	ok                the answer is read
//	not_found         a 404, which is also unavailable
//	redirect_refused  a 3xx answering a key-directory read, which is also unavailable
//	unavailable       any other failure
//
// Only terminal answers are recorded: a read that follows a redirect needs a second
// answer, and following is not this decision. A Location the HTTP client cannot parse
// is left out too: Go's and Python's clients reject that answer before the read sees
// its status, TypeScript's read sees the status first, and each SDK pins its own side
// in its tests.
//
// The verdicts are emitted by RUNNING the shared GET against a server that answers
// each case — Go is the oracle, never a hand-authored table. Default `go test` asserts
// the committed file matches a fresh emit; FORA_UPDATE_VECTORS=1 rewrites it.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// documentFetchVector is one answer to a document read and what the read reports.
type documentFetchVector struct {
	Name string `json:"name"`
	//: "key_directory" for a read that refuses every redirect, "document" for one
	//: that may follow them.
	Read string `json:"read"`
	//: The status the server answered with.
	Status int `json:"status"`
	//: The Location it answered with, "" when it sent none.
	Location string `json:"location"`
	//: What the read reports: ok, not_found, redirect_refused or unavailable.
	Verdict string `json:"verdict"`
}

// elsewhereDirectory is a Location naming another origin's key directory.
const elsewhereDirectory = "https://elsewhere.example/.well-known/http-message-signatures-directory"

// documentFetchCases enumerate the answers whose verdict must not drift, without it.
func documentFetchCases() []documentFetchVector {
	dir := func(name string, status int, location string) documentFetchVector {
		return documentFetchVector{Name: "key_directory_" + name, Read: "key_directory", Status: status, Location: location}
	}
	doc := func(name string, status int, location string) documentFetchVector {
		return documentFetchVector{Name: "document_" + name, Read: "document", Status: status, Location: location}
	}
	return []documentFetchVector{
		// The controls: an answer each read takes.
		dir("ok", http.StatusOK, ""),
		doc("ok", http.StatusOK, ""),

		// A document that is not there, on either read.
		dir("not_found", http.StatusNotFound, ""),
		doc("not_found", http.StatusNotFound, ""),

		// Answers that are no document and no redirect. A 403 and a 410 are refusals
		// of a sort, and not the 404 a caller may read as "absent".
		dir("forbidden", http.StatusForbidden, ""),
		dir("gone", http.StatusGone, ""),
		dir("server_error", http.StatusInternalServerError, ""),
		dir("unavailable", http.StatusServiceUnavailable, ""),
		doc("forbidden", http.StatusForbidden, ""),
		doc("gone", http.StatusGone, ""),
		doc("unavailable", http.StatusServiceUnavailable, ""),

		// Every redirect a key directory might answer with, followable or not, to
		// another origin, relative, carrying credentials, or out of http(s).
		dir("moved_permanently", http.StatusMovedPermanently, elsewhereDirectory),
		dir("found", http.StatusFound, elsewhereDirectory),
		dir("see_other", http.StatusSeeOther, elsewhereDirectory),
		dir("temporary_redirect", http.StatusTemporaryRedirect, elsewhereDirectory),
		dir("permanent_redirect", http.StatusPermanentRedirect, elsewhereDirectory),
		dir("found_relative", http.StatusFound, "/elsewhere"),
		dir("found_with_credentials", http.StatusFound, "https://user:secret@elsewhere.example/d?token=t"),
		dir("found_not_http", http.StatusFound, "ftp://elsewhere.example/d"),
		dir("found_no_location", http.StatusFound, ""),
		dir("multiple_choices", http.StatusMultipleChoices, elsewhereDirectory),
		dir("not_modified", http.StatusNotModified, ""),

		// The 3xx answers a read that may follow redirects does not follow.
		doc("found_no_location", http.StatusFound, ""),
		doc("multiple_choices", http.StatusMultipleChoices, elsewhereDirectory),
		doc("not_modified", http.StatusNotModified, ""),
	}
}

// TestGenerateDocumentFetchVectors emits the document-fetch golden corpus.
func TestGenerateDocumentFetchVectors(t *testing.T) {
	cases := documentFetchCases()
	vectors := make([]documentFetchVector, 0, len(cases))
	for _, c := range cases {
		verdict, ok := documentFetchVerdict(readDocumentAnswer(t, c))
		if !ok {
			t.Fatalf("%s: the read failed with an error the corpus has no verdict for", c.Name)
		}
		c.Verdict = verdict
		vectors = append(vectors, c)
	}
	emitOrCheck(t, filepath.Join("testdata", "document-fetch-vectors.json"), map[string]any{
		"note": "The verdict a document read reports for each status it can be answered with, " +
			"derived by driving the shared GET. A key_directory read refuses every 3xx; a " +
			"document read may follow redirects, so only the 3xx answers it does not follow " +
			"are recorded. not_found and redirect_refused are also unavailable.",
		"vectors": vectors,
	})
}

// readDocumentAnswer serves v's answer and reads it as v's read does.
func readDocumentAnswer(t *testing.T, v documentFetchVector) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if v.Location != "" {
			w.Header().Set("Location", v.Location)
		}
		w.WriteHeader(v.Status)
	}))
	defer srv.Close()
	read := fetchDocument
	if v.Read == "key_directory" {
		read = fetchDocumentNoRedirect
	}
	_, err := read(context.Background(), srv.Client(), srv.URL+"/document")
	return err
}

// documentFetchVerdict names the verdict err carries, the most specific first. ok is
// false for a failure that is not ErrDirectoryUnavailable, which the emitter refuses
// to record rather than invent a word for.
func documentFetchVerdict(err error) (verdict string, ok bool) {
	switch {
	case err == nil:
		return "ok", true
	case !errors.Is(err, ErrDirectoryUnavailable):
		return "", false
	case errors.Is(err, ErrRedirectRefused):
		return "redirect_refused", true
	case errors.Is(err, ErrDocumentNotFound):
		return "not_found", true
	default:
		return "unavailable", true
	}
}
