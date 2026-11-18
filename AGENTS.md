# Go SDK instructions

These instructions supplement the repository-root `AGENTS.md`.

- Keep this module independently buildable; validate changes with
  `go test ./...` and `go vet ./...`.
- The CLI consumes this module through its local `replace` directive. Preserve
  its public API compatibility unless a coordinated CLI change is intended.
- The RASP tests read copies of the shared `sdk/rasp` fixtures from
  `rasp/testdata/shared/`, so the public mirror tests on its own. After
  changing a file in `sdk/rasp/testdata` or `sdk/rasp/rules`, run
  `bash sdk/go/scripts/sync-shared-testdata.sh` and commit the copies; CI runs
  it with `--check`.
