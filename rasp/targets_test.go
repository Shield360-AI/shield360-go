package rasp

import (
	"context"
	"strings"
	"testing"
)

// Allow-list targets (sdk/rasp/README.md "Allow-list targets"): the shared
// conformance cases (sdk/rasp/testdata/targets.json), the detectors that set
// the raw target and the dialect, and the event attributes.

func TestTargetConformance(t *testing.T) {
	v := loadJSON(t, "testdata/targets.json")
	masks, dirs := v["mask"].([]any), v["directory"].([]any)
	if len(masks) == 0 || len(dirs) == 0 {
		t.Fatal("no cases")
	}
	for _, raw := range masks {
		c := raw.(map[string]any)
		in := c["raw"].(string)
		got, ok := MaskTarget(in)
		if want, isStr := c["target"].(string); isStr {
			if !ok || got != want {
				t.Errorf("MaskTarget(%q) = %q, %v, want %q", in, got, ok, want)
			}
		} else if ok {
			t.Errorf("MaskTarget(%q) = %q, want left out", in, got)
		}
	}
	for _, raw := range dirs {
		c := raw.(map[string]any)
		resolved, want := c["resolved"].(string), c["directory"].(string)
		if got := TargetDirectory(resolved); got != want {
			t.Errorf("TargetDirectory(%q) = %q, want %q", resolved, got, want)
		}
	}
}

func TestDetectorsSetTargetAndDialect(t *testing.T) {
	if f := DetectShellSpawn(Spawn{Argv0: `C:\Windows\System32\CMD.EXE`, InRequest: true}); f == nil || f.Target != "cmd" {
		t.Errorf("shell_spawn %+v", f)
	}
	if f := DetectOutbound("https://API.Evil.example:8443/x?q=1", []string{"api.example.com"}, nil); f == nil || f.Target != "api.evil.example" {
		t.Errorf("outbound %+v", f)
	}
	in := []Input{{Source: SourceRequest, Key: "query.f", Value: "../etc/passwd"}}
	if f := DetectPath("/srv/app/../../etc/passwd", OpRead, in, []string{"/srv/app"}, true); f == nil || f.Target != "" {
		t.Errorf("traversal carries no target: %+v", f)
	}
	in = []Input{{Source: SourceRequest, Key: "query.f", Value: "report.txt"}}
	if f := DetectPath("/var/data/report.txt", OpRead, in, []string{"/srv/app"}, true); f == nil || f.Rule != "path.outside_root" || f.Target != "/var/data" {
		t.Errorf("outside_root %+v", f)
	}
	sqlIn := []Input{{Source: SourceRequest, Key: "query.id", Value: "1 OR 1=1"}}
	if f := DetectSQL("SELECT * FROM t WHERE id = 1 OR 1=1", sqlIn, DialectPostgres); f == nil || f.Dialect != DialectPostgres {
		t.Errorf("sql %+v", f)
	}
	if f := DetectSQL("SELECT * FROM t WHERE id = 1 OR 1=1", sqlIn, ""); f == nil || f.Dialect != DialectGeneric {
		t.Errorf("sql default dialect %+v", f)
	}
}

func TestTargetEventAttributes(t *testing.T) {
	ctx := context.Background()
	targetOf := func(t *testing.T, r *RemoteConfig, f Finding) (string, bool) {
		log := setupEngine(t, engineSettings{})
		if r != nil {
			setRemoteConfig(r)
		}
		_, _ = HandleFinding(ctx, &f, "http.request", FindingExtra{})
		v, ok := log.all()[0].Attrs["shield360.rasp.target"]
		return v, ok
	}
	host := Finding{Attack: Outbound, Rule: "outbound.not_allowed", Target: "api.example.com"}
	on := remote(func(r *RemoteConfig) { r.ReportTargets = true })

	t.Run("only with the signed reportTargets flag", func(t *testing.T) {
		if v, ok := targetOf(t, on, host); !ok || v != "api.example.com" {
			t.Errorf("target %q %v", v, ok)
		}
		if _, ok := targetOf(t, remote(nil), host); ok {
			t.Error("target with reportTargets false")
		}
		if _, ok := targetOf(t, nil, host); ok {
			t.Error("target without a signed config")
		}
	})
	t.Run("only for the three allow-list rules", func(t *testing.T) {
		for _, rule := range []string{"shell_spawn.shell", "path.outside_root"} {
			f := Finding{Attack: PathTraversal, Rule: rule, Target: "/var/data"}
			if _, ok := targetOf(t, on, f); !ok {
				t.Errorf("%s: no target", rule)
			}
		}
		f := Finding{Attack: PathTraversal, Rule: "path.traversal", Target: "/var/data"}
		if _, ok := targetOf(t, on, f); ok {
			t.Error("path.traversal carries a target")
		}
	})
	t.Run("masked piece by piece and never cut", func(t *testing.T) {
		f := host
		f.Target = strings.Repeat("a", 30) + ".example.com"
		if v, _ := targetOf(t, on, f); v != "***.example.com" {
			t.Errorf("masked %q", v)
		}
		f.Target = strings.Repeat("/ab", 90)
		if v, ok := targetOf(t, on, f); ok {
			t.Errorf("over 256 characters sent: %q", v)
		}
	})
	t.Run("SQL findings carry the dialect, whatever reportTargets says", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		f := Finding{Attack: SQLInjection, Rule: "sqli.userinput", Input: &Input{Value: "v", Key: "query.id", Source: SourceRequest}, Dialect: DialectMySQL}
		_, _ = HandleFinding(ctx, &f, "db.mysql.query", FindingExtra{})
		f.Rule, f.Dialect = "sqli.stacked", SQLDialect("bogus")
		_, _ = HandleFinding(ctx, &f, "db.mysql.query", FindingExtra{})
		ev := log.all()
		if got := ev[0].Attrs["shield360.rasp.sql.dialect"]; got != "mysql" {
			t.Errorf("dialect %q", got)
		}
		if _, ok := ev[1].Attrs["shield360.rasp.sql.dialect"]; ok {
			t.Error("unknown dialect sent")
		}
		if _, ok := ev[0].Attrs["shield360.rasp.target"]; ok {
			t.Error("SQL event carries a target")
		}
	})
}
