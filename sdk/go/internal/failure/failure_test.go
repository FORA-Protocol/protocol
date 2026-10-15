package failure

import (
	"net/http"
	"reflect"
	"testing"
)

// RefusalHeader is the one place the rule lives: an error answer's fields are
// copied, and every other answer carries none, a redirect's Location included.
func TestRefusalHeader_CarriesOnlyAnErrorAnswersFields(t *testing.T) {
	answer := http.Header{
		"Accept-Signature": {`sig1=("@method");tag="web-bot-auth"`},
		"Location":         {"https://elsewhere.test/next?token=s3cret"},
	}
	for _, status := range []int{0, 100, 200, 204, 301, 302, 304, 399} {
		if got := RefusalHeader(status, answer); got != nil {
			t.Errorf("status %d carries %v, want nil", status, got)
		}
	}
	for _, status := range []int{400, 401, 403, 429, 500, 503, 599} {
		got := RefusalHeader(status, answer)
		if !reflect.DeepEqual(got, answer) {
			t.Errorf("status %d carries %v, want %v", status, got, answer)
		}
	}
	if got := RefusalHeader(http.StatusUnauthorized, nil); got != nil {
		t.Errorf("no fields carries %v, want nil", got)
	}
}

// The copy is the caller's: changing it leaves the answer it came from untouched.
func TestRefusalHeader_ReturnsACopy(t *testing.T) {
	answer := http.Header{"Retry-After": {"120"}}
	got := RefusalHeader(http.StatusServiceUnavailable, answer)
	got.Set("Retry-After", "0")
	if answer.Get("Retry-After") != "120" {
		t.Errorf("the copy shares storage with the answer: %v", answer)
	}
}
