#!/usr/bin/env bash
# Copy the shared RASP fixtures the Go SDK's tests read into
# sdk/go/rasp/testdata/shared/, so the module tests on its own (the public
# shield360-go mirror has no sdk/rasp). The layout under shared/ follows
# sdk/rasp (testdata/, rules/).
#
#   bash sdk/go/scripts/sync-shared-testdata.sh          # refresh the copies
#   bash sdk/go/scripts/sync-shared-testdata.sh --check  # fail when a copy drifted
#
# sdk/rasp stays the source of truth; edit it there, then rerun this.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
dest="$root/sdk/go/rasp/testdata/shared"
check=0
[ "${1:-}" = "--check" ] && check=1

# Paths relative to sdk/rasp, copied to the same path under $dest.
files=(
	testdata/ai-attack-agents.json
	testdata/attack-examples.json
	testdata/benign.json
	testdata/custom-rules.json
	testdata/deception.json
	testdata/dnslog-domains.json
	testdata/iast.json
	testdata/request-correlation.json
	testdata/routes.json
	testdata/sql-lexer.json
	testdata/targets.json
	testdata/template-attack-examples.json
	testdata/triangle.json
	rules/default-rules.json
	rules/template-engines.json
)

drift=0
for f in "${files[@]}"; do
	src="$root/sdk/rasp/$f"
	dst="$dest/$f"
	if [ "$check" = 1 ]; then
		if ! cmp -s "$src" "$dst"; then
			echo "drift: sdk/go/rasp/testdata/shared/$f differs from sdk/rasp/$f" >&2
			drift=1
		fi
	else
		mkdir -p "$(dirname "$dst")"
		cp "$src" "$dst"
	fi
done

if [ "$check" = 1 ]; then
	# Nothing extra may sit in the shared directory.
	want=$(printf '%s\n' "${files[@]}" | sort)
	have=$(cd "$dest" && find . -type f | sed 's|^\./||' | sort)
	if [ "$want" != "$have" ]; then
		echo "drift: sdk/go/rasp/testdata/shared has files this script does not manage" >&2
		drift=1
	fi
	if [ "$drift" = 1 ]; then
		echo "Run bash sdk/go/scripts/sync-shared-testdata.sh and commit the result." >&2
		exit 1
	fi
	echo "shared test fixtures are in sync"
fi
