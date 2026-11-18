package shield360

import (
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"unicode"

	"go.opentelemetry.io/otel/attribute"
)

// Build and VCS resource attributes (OTel VCS registry).
const (
	attrServiceVersion = "service.version"
	attrVCSRevision    = "vcs.ref.head.revision"
	attrVCSRepoURL     = "vcs.repository.url.full"
	attrVCSRefName     = "vcs.ref.head.name"

	maxBuildValueLen = 256
)

var (
	revisionPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	hostPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	scpPattern      = regexp.MustCompile(`^(?:[^@/:]+@)?([^@/:]+):(.+)$`)
)

// buildValues holds the raw (unsanitised) candidates for one precedence level.
type buildValues struct{ version, revision, repoURL, refName string }

// ciProvider reads revision, repository URL and ref from one CI platform.
type ciProvider func(env func(string) string) buildValues

var vercelHosts = map[string]string{"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}

// ciProviders are tried in order; the first whose revision is set supplies
// all CI values, so providers are never mixed.
var ciProviders = []ciProvider{
	func(env func(string) string) buildValues { // GitHub Actions
		v := buildValues{revision: env("GITHUB_SHA"), refName: firstNonEmpty(env("GITHUB_HEAD_REF"), env("GITHUB_REF_NAME"))}
		if repo := env("GITHUB_REPOSITORY"); repo != "" {
			v.repoURL = firstNonEmpty(env("GITHUB_SERVER_URL"), "https://github.com") + "/" + repo
		}
		return v
	},
	func(env func(string) string) buildValues { // GitLab CI
		return buildValues{revision: env("CI_COMMIT_SHA"), repoURL: env("CI_PROJECT_URL"), refName: env("CI_COMMIT_REF_NAME")}
	},
	func(env func(string) string) buildValues { // Vercel
		v := buildValues{revision: env("VERCEL_GIT_COMMIT_SHA"), refName: env("VERCEL_GIT_COMMIT_REF")}
		host, owner, slug := vercelHosts[env("VERCEL_GIT_PROVIDER")], env("VERCEL_GIT_REPO_OWNER"), env("VERCEL_GIT_REPO_SLUG")
		if host != "" && owner != "" && slug != "" {
			v.repoURL = "https://" + host + "/" + owner + "/" + slug
		}
		return v
	},
	func(env func(string) string) buildValues { // Netlify
		return buildValues{revision: env("COMMIT_REF"), repoURL: env("REPOSITORY_URL"), refName: env("BRANCH")}
	},
	func(env func(string) string) buildValues { // Render: repository host unknown
		return buildValues{revision: env("RENDER_GIT_COMMIT"), refName: env("RENDER_GIT_BRANCH")}
	},
	func(env func(string) string) buildValues { // Railway
		v := buildValues{revision: env("RAILWAY_GIT_COMMIT_SHA"), refName: env("RAILWAY_GIT_BRANCH")}
		if owner, name := env("RAILWAY_GIT_REPO_OWNER"), env("RAILWAY_GIT_REPO_NAME"); owner != "" && name != "" {
			v.repoURL = "https://github.com/" + owner + "/" + name
		}
		return v
	},
	func(env func(string) string) buildValues { // Heroku
		return buildValues{revision: firstNonEmpty(env("HEROKU_SLUG_COMMIT"), env("SOURCE_VERSION"))}
	},
	func(env func(string) string) buildValues { // AWS CodeBuild
		return buildValues{
			revision: env("CODEBUILD_RESOLVED_SOURCE_VERSION"),
			repoURL:  env("CODEBUILD_SOURCE_REPO_URL"),
			refName:  strings.TrimPrefix(env("CODEBUILD_WEBHOOK_HEAD_REF"), "refs/heads/"),
		}
	},
	func(env func(string) string) buildValues { // Buildkite
		return buildValues{revision: env("BUILDKITE_COMMIT"), repoURL: env("BUILDKITE_REPO"), refName: env("BUILDKITE_BRANCH")}
	},
	func(env func(string) string) buildValues { // CircleCI
		return buildValues{revision: env("CIRCLE_SHA1"), repoURL: env("CIRCLE_REPOSITORY_URL"), refName: env("CIRCLE_BRANCH")}
	},
	func(env func(string) string) buildValues { // Bitbucket Pipelines
		return buildValues{revision: env("BITBUCKET_COMMIT"), repoURL: env("BITBUCKET_GIT_HTTP_ORIGIN"), refName: env("BITBUCKET_BRANCH")}
	},
	func(env func(string) string) buildValues { // Azure Pipelines
		return buildValues{revision: env("BUILD_SOURCEVERSION"), repoURL: env("BUILD_REPOSITORY_URI"), refName: env("BUILD_SOURCEBRANCHNAME")}
	},
	func(env func(string) string) buildValues { // Jenkins / generic
		return buildValues{revision: env("GIT_COMMIT"), repoURL: env("GIT_URL"), refName: strings.TrimPrefix(env("GIT_BRANCH"), "origin/")}
	},
}

// resolveBuildAttributes returns service.version and vcs.* attributes. Per
// attribute the first valid value wins: explicit config and SHIELD360_* env,
// OTel env (an operator's explicit OTel setting), the binary's embedded
// vcs.revision, then one CI provider (never mixed across providers).
func resolveBuildAttributes(cfg Config, env func(string) string, embeddedRevision string) []attribute.KeyValue {
	levels := []buildValues{
		{
			version:  firstNonEmpty(cfg.ServiceVersion, env("SHIELD360_SERVICE_VERSION")),
			revision: env("SHIELD360_GIT_COMMIT"),
			repoURL:  env("SHIELD360_GIT_REPOSITORY_URL"),
			refName:  env("SHIELD360_GIT_BRANCH"),
		},
		otelEnvValues(env),
		{revision: embeddedRevision},
		ciValues(env),
	}

	var out buildValues
	for _, l := range levels {
		if out.version == "" {
			out.version = sanitizeText(l.version)
		}
		if out.revision == "" {
			out.revision = sanitizeRevision(l.revision)
		}
		if out.repoURL == "" {
			out.repoURL = sanitizeRepoURL(l.repoURL)
		}
		if out.refName == "" {
			out.refName = sanitizeText(l.refName)
		}
	}

	var attrs []attribute.KeyValue
	for _, kv := range []struct{ key, value string }{
		{attrServiceVersion, out.version},
		{attrVCSRevision, out.revision},
		{attrVCSRepoURL, out.repoURL},
		{attrVCSRefName, out.refName},
	} {
		if kv.value != "" {
			attrs = append(attrs, attribute.String(kv.key, kv.value))
		}
	}
	return attrs
}

// ciValues returns the values of the first CI provider whose revision is set.
// CI never supplies service.version.
func ciValues(env func(string) string) buildValues {
	for _, p := range ciProviders {
		if v := p(env); strings.TrimSpace(v.revision) != "" {
			v.version = ""
			return v
		}
	}
	return buildValues{}
}

// otelEnvValues reads OTEL_SERVICE_VERSION and OTEL_RESOURCE_ATTRIBUTES.
func otelEnvValues(env func(string) string) buildValues {
	attrs := parseResourceAttributes(env("OTEL_RESOURCE_ATTRIBUTES"))
	return buildValues{
		version:  firstNonEmpty(env("OTEL_SERVICE_VERSION"), attrs[attrServiceVersion]),
		revision: attrs[attrVCSRevision],
		repoURL:  attrs[attrVCSRepoURL],
		refName:  attrs[attrVCSRefName],
	}
}

// parseResourceAttributes parses comma-separated k=v pairs with
// percent-encoded values; malformed pairs are skipped.
func parseResourceAttributes(raw string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if decoded, err := url.PathUnescape(strings.TrimSpace(v)); err == nil {
			out[strings.TrimSpace(k)] = decoded
		}
	}
	return out
}

// buildRevision returns the vcs.revision that `go build` embeds when the
// binary is built inside a checkout.
func buildRevision() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}

func sanitizeRevision(raw string) string {
	raw = strings.TrimSpace(raw)
	if !revisionPattern.MatchString(raw) {
		return ""
	}
	return strings.ToLower(raw)
}

// sanitizeText trims, strips control characters and caps the length.
func sanitizeText(raw string) string {
	cleaned := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, raw))
	if runes := []rune(cleaned); len(runes) > maxBuildValueLen {
		cleaned = strings.TrimSpace(string(runes[:maxBuildValueLen]))
	}
	return cleaned
}

// sanitizeRepoURL normalises a repository URL to scheme://host/owner/repo,
// dropping credentials, query, fragment and a trailing .git. Only http(s),
// ssh, git and scp-style URLs are accepted; ssh forms become https.
func sanitizeRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	scheme, host, port, path := "https", "", "", ""
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "http":
			scheme, port = strings.ToLower(u.Scheme), u.Port() // http(s) keeps its port
		case "ssh", "git":
		default:
			return ""
		}
		host, path = u.Hostname(), u.Path
	} else if m := scpPattern.FindStringSubmatch(raw); m != nil {
		host, path = m[1], m[2]
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
	} else {
		return ""
	}

	host = strings.ToLower(host)
	if !hostPattern.MatchString(host) {
		return ""
	}
	if port != "" {
		host += ":" + port
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}
	return scheme + "://" + host + "/" + path
}
