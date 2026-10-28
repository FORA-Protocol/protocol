package helpers_test

import (
	"reflect"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func TestNormalizeScopes(t *testing.T) {
	got := helpers.NormalizeScopes([]string{"archive.read", "news.read", "", "news.read"})
	want := []string{"archive.read", "news.read"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if helpers.NormalizeScopes(nil) != nil {
		t.Error("nil in -> nil out")
	}
	if helpers.NormalizeScopes([]string{"", ""}) != nil {
		t.Error("all-empty -> nil")
	}
}

func TestApplyScopes(t *testing.T) {
	r := &forav1.Requester{Id: "agent"}
	helpers.ApplyScopes(r, "news.read", "archive.read", "news.read")
	if !reflect.DeepEqual(r.GetScopes(), []string{"archive.read", "news.read"}) {
		t.Errorf("scopes = %v", r.GetScopes())
	}
	helpers.ApplyScopes(nil) // must not panic
}

func TestScopesSubset(t *testing.T) {
	granted := []string{"news.read", "archive.read", "video.read"}
	if !helpers.ScopesSubset([]string{"news.read", "video.read"}, granted) {
		t.Error("valid subset should pass")
	}
	if helpers.ScopesSubset([]string{"news.write"}, granted) {
		t.Error("scope outside the grant must fail (over-broad delegation)")
	}
	if !helpers.ScopesSubset(nil, granted) {
		t.Error("empty subset is always a subset")
	}
	if !helpers.ScopesSubset([]string{"publisher:news:read"}, []string{"publisher:*:read"}) {
		t.Error("a child may narrow a parent wildcard")
	}
	if helpers.ScopesSubset([]string{"publisher:news:*"}, []string{"publisher:*:read"}) {
		t.Error("a child may not widen the parent grant")
	}
}

func TestScopeCovers(t *testing.T) {
	if !helpers.ScopeCovers("dist:*", "dist:US:CA") {
		t.Error("terminal wildcard covers all remaining segments")
	}
	if helpers.ScopeCovers("dist", "dist:US") {
		t.Error("no implicit prefix match")
	}
	if !helpers.ScopesCover([]string{"dist:*", "credit:read"}, []string{"dist:US", "credit:read"}) {
		t.Error("every required scope is covered by some grant")
	}
	if helpers.ScopesCover(nil, []string{"credit:read"}) {
		t.Error("an empty grant covers nothing")
	}
}
