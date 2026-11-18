package shield360

import (
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaC = "cccccccccccccccccccccccccccccccccccccccc"
)

func resolveWith(cfg Config, env map[string]string, embedded string) map[string]string {
	out := map[string]string{}
	for _, kv := range resolveBuildAttributes(cfg, func(k string) string { return env[k] }, embedded) {
		out[string(kv.Key)] = kv.Value.AsString()
	}
	return out
}

func TestBuildAttributesPrecedence(t *testing.T) {
	ci := map[string]string{
		"GITHUB_SHA":               shaC,
		"GITHUB_REPOSITORY":        "acme/ci",
		"GITHUB_REF_NAME":          "ci-branch",
		"OTEL_SERVICE_VERSION":     "otel-version",
		"OTEL_RESOURCE_ATTRIBUTES": "vcs.ref.head.revision=" + shaB + ",vcs.ref.head.name=otel-branch",
	}

	// Level 2 (OTel env) beats CI per attribute; CI fills only what OTel
	// left unset (here the repository) and never sets service.version.
	got := resolveWith(Config{}, ci, "")
	want := map[string]string{
		attrServiceVersion: "otel-version",
		attrVCSRevision:    shaB,
		attrVCSRepoURL:     "https://github.com/acme/ci",
		attrVCSRefName:     "otel-branch",
	}
	assertAttrs(t, "otel over ci", got, want)

	// OTel env also beats the embedded vcs.revision.
	got = resolveWith(Config{}, ci, shaA)
	assertAttrs(t, "otel over embedded", got, want)

	// Level 3 (embedded vcs.revision) beats CI for the revision only.
	ciOnly := map[string]string{}
	for k, v := range ci {
		if !strings.HasPrefix(k, "OTEL_") {
			ciOnly[k] = v
		}
	}
	got = resolveWith(Config{}, ciOnly, strings.ToUpper(shaA))
	assertAttrs(t, "embedded", got, map[string]string{
		attrVCSRevision: shaA,
		attrVCSRepoURL:  "https://github.com/acme/ci",
		attrVCSRefName:  "ci-branch",
	})

	// Level 4 (CI) alone.
	got = resolveWith(Config{}, ciOnly, "")
	assertAttrs(t, "ci", got, map[string]string{
		attrVCSRevision: shaC,
		attrVCSRepoURL:  "https://github.com/acme/ci",
		attrVCSRefName:  "ci-branch",
	})

	// An invalid OTel revision falls through to CI.
	ciOnly["OTEL_RESOURCE_ATTRIBUTES"] = "vcs.ref.head.revision=HEAD"
	if got := resolveWith(Config{}, ciOnly, "")[attrVCSRevision]; got != shaC {
		t.Errorf("invalid OTel revision should fall through to CI, got %q", got)
	}

	// Level 1 (config, then SHIELD360_* env) beats everything.
	env := map[string]string{
		"SHIELD360_SERVICE_VERSION":    "env-version",
		"SHIELD360_GIT_COMMIT":         shaB,
		"SHIELD360_GIT_REPOSITORY_URL": "git@gitlab.com:acme/explicit.git",
		"SHIELD360_GIT_BRANCH":         "release/1",
	}
	for k, v := range ci {
		env[k] = v
	}
	got = resolveWith(Config{}, env, shaA)
	assertAttrs(t, "explicit env", got, map[string]string{
		attrServiceVersion: "env-version",
		attrVCSRevision:    shaB,
		attrVCSRepoURL:     "https://gitlab.com/acme/explicit",
		attrVCSRefName:     "release/1",
	})
	if got := resolveWith(Config{ServiceVersion: "1.2.3"}, env, "")[attrServiceVersion]; got != "1.2.3" {
		t.Errorf("Config.ServiceVersion should win, got %q", got)
	}

	// OTel env alone.
	got = resolveWith(Config{}, map[string]string{
		"OTEL_RESOURCE_ATTRIBUTES": "service.version=2.0%2Bbuild, vcs.repository.url.full=https%3A%2F%2Fgithub.com%2Facme%2Fapi.git,bad,vcs.ref.head.revision=nothex",
	}, "")
	assertAttrs(t, "otel", got, map[string]string{
		attrServiceVersion: "2.0+build",
		attrVCSRepoURL:     "https://github.com/acme/api",
	})

	if got := resolveWith(Config{}, nil, ""); len(got) != 0 {
		t.Errorf("nothing configured should add nothing, got %v", got)
	}
}

func TestBuildAttributesProvidersNotMixed(t *testing.T) {
	// GitLab has no revision, so it is skipped entirely; Netlify wins and its
	// branch is used even though GitLab's branch var is set.
	got := resolveWith(Config{}, map[string]string{
		"CI_PROJECT_URL":     "https://gitlab.com/acme/gl",
		"CI_COMMIT_REF_NAME": "gl-branch",
		"COMMIT_REF":         shaA,
		"BRANCH":             "netlify-branch",
	}, "")
	assertAttrs(t, "netlify", got, map[string]string{attrVCSRevision: shaA, attrVCSRefName: "netlify-branch"})

	// Render never guesses a repository; Jenkins branch loses origin/.
	got = resolveWith(Config{}, map[string]string{"RENDER_GIT_COMMIT": shaA, "GIT_URL": "https://github.com/acme/j"}, "")
	if _, ok := got[attrVCSRepoURL]; ok {
		t.Errorf("render must not take another provider's repo: %v", got)
	}
	got = resolveWith(Config{}, map[string]string{"GIT_COMMIT": shaA, "GIT_BRANCH": "origin/main"}, "")
	if got[attrVCSRefName] != "main" {
		t.Errorf("jenkins branch = %q", got[attrVCSRefName])
	}
	got = resolveWith(Config{}, map[string]string{
		"VERCEL_GIT_COMMIT_SHA": shaA, "VERCEL_GIT_PROVIDER": "gitlab",
		"VERCEL_GIT_REPO_OWNER": "acme", "VERCEL_GIT_REPO_SLUG": "web",
	}, "")
	if got[attrVCSRepoURL] != "https://gitlab.com/acme/web" {
		t.Errorf("vercel repo = %q", got[attrVCSRepoURL])
	}
}

func TestSanitizeRepoURL(t *testing.T) {
	cases := map[string]string{
		"https://x-access-token:ghp_abc@github.com/acme/api.git": "https://github.com/acme/api",
		"git@github.com:acme/api.git":                            "https://github.com/acme/api",
		"ssh://git@github.com:22/acme/api.git":                   "https://github.com/acme/api",
		"git://github.com/acme/api":                              "https://github.com/acme/api",
		"http://git.internal.example:8080/acme/api/?x=1#y":       "http://git.internal.example:8080/acme/api",
		"HTTPS://GitHub.com/acme/api/":                           "https://github.com/acme/api",
		"/home/bob/repo":                                         "",
		"file:///srv/repo.git":                                   "",
		"ftp://github.com/acme/api":                              "",
		"https://github.com":                                     "",
		"https://bad_host/acme/api":                              "",
		"C:/repo":                                                "",
		"":                                                       "",
	}
	for in, want := range cases {
		if got := sanitizeRepoURL(in); got != want {
			t.Errorf("sanitizeRepoURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeRevisionAndText(t *testing.T) {
	if got := sanitizeRevision("  ABCDEF1 "); got != "abcdef1" {
		t.Errorf("got %q", got)
	}
	for _, bad := range []string{"abc", "not-a-sha", strings.Repeat("a", 65)} {
		if got := sanitizeRevision(bad); got != "" {
			t.Errorf("sanitizeRevision(%q) = %q, want dropped", bad, got)
		}
	}
	if got := sanitizeText(" main\x00\n "); got != "main" {
		t.Errorf("got %q", got)
	}
	if got := sanitizeText(strings.Repeat("x", 300)); len(got) != maxBuildValueLen {
		t.Errorf("len = %d", len(got))
	}
}

func TestNewResourceHasBuildAttributes(t *testing.T) {
	// Hermetic on CI runners: no provider revision var may be set.
	for _, k := range []string{"GITHUB_SHA", "CI_COMMIT_SHA", "VERCEL_GIT_COMMIT_SHA", "COMMIT_REF",
		"RENDER_GIT_COMMIT", "RAILWAY_GIT_COMMIT_SHA", "HEROKU_SLUG_COMMIT", "SOURCE_VERSION",
		"CODEBUILD_RESOLVED_SOURCE_VERSION", "BUILDKITE_COMMIT", "CIRCLE_SHA1", "BITBUCKET_COMMIT",
		"BUILD_SOURCEVERSION", "GIT_COMMIT", "SHIELD360_GIT_BRANCH"} {
		t.Setenv(k, "")
	}
	t.Setenv("SHIELD360_GIT_COMMIT", shaA)
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "vcs.ref.head.name=from-otel")
	res, err := newResource(Config{ApplicationName: "app", ServiceVersion: "9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	set := res.Set()
	for key, want := range map[string]string{
		attrServiceVersion: "9.9.9",
		attrVCSRevision:    shaA,
		attrVCSRefName:     "from-otel",
	} {
		if v, ok := set.Value(attribute.Key(key)); !ok || v.AsString() != want {
			t.Errorf("resource %s = %q, want %q", key, v.AsString(), want)
		}
	}
}

func assertAttrs(t *testing.T, name string, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v, want %v", name, got, want)
		return
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s = %q, want %q", name, k, got[k], v)
		}
	}
}
