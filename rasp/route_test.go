package rasp

import (
	"context"
	"testing"
)

// Event route (sdk/rasp/README.md "Event route"): the shared conformance cases
// (sdk/rasp/testdata/routes.json), and attack events built from a path when
// the framework gives no route template.

func TestEventRouteConformance(t *testing.T) {
	cases := loadJSON(t, "testdata/routes.json")["cases"].([]any)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, raw := range cases {
		c := raw.(map[string]any)
		path, want := c["path"].(string), c["route"].(string)
		if got := EventRouteOf(path); got != want {
			t.Errorf("EventRouteOf(%q) = %q, want %q", path, got, want)
		}
		// Passive IAST masks a route the same way (README "Passive IAST: Route").
		if got := IastRouteOf(path); got != want {
			t.Errorf("IastRouteOf(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestAttackEventRoute(t *testing.T) {
	ctx := context.Background()
	f := Finding{Attack: SQLInjection, Rule: "sqli.userinput", Input: &Input{Value: "v", Key: "query.id", Source: SourceRequest}}
	routeOfEvent := func(t *testing.T, rc *Context, extra FindingExtra) string {
		log := setupEngine(t, engineSettings{})
		fc := f
		_, _ = HandleFinding(withContext(ctx, rc), &fc, "database/sql.Query", extra)
		return log.all()[0].Attrs["shield360.rasp.route"]
	}

	t.Run("never carries a secret-looking path segment when the framework gives no template", func(t *testing.T) {
		rc := &Context{inRequest: true, method: "get", path: "/reset/Zx9TqLm2Rk7WpA4s/confirm"}
		if got := routeOfEvent(t, rc, FindingExtra{}); got != "/reset/:id/confirm" {
			t.Errorf("route %q", got)
		}
	})
	t.Run("keeps the framework route template unchanged", func(t *testing.T) {
		rc := &Context{inRequest: true, method: "get", path: "/reset/Zx9TqLm2Rk7WpA4s/confirm", route: "/reset/{Token}/confirm"}
		if got := routeOfEvent(t, rc, FindingExtra{}); got != "/reset/{Token}/confirm" {
			t.Errorf("route %q", got)
		}
	})
	t.Run("keeps a route passed by the hook unchanged", func(t *testing.T) {
		rc := &Context{inRequest: true, method: "get"}
		if got := routeOfEvent(t, rc, FindingExtra{Route: "/Files/{fileName}", Path: "/Files/Secret"}); got != "/Files/{fileName}" {
			t.Errorf("route %q", got)
		}
	})
}
