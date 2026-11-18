package rasp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fileFixture makes dir/kit.txt and dir/sub, and returns dir.
func fileFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kit.txt"), []byte("kit"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// traversal is the input and a path holding it (dir/sub/../kit.txt).
const traversal = "../kit.txt"

func traversalInputs() []Input { return AddInput(nil, traversal, "query.file") }

func TestFileHelpersContract(t *testing.T) {
	runSinkContract(t, sinkCase{
		name:   "rasp.ReadFile",
		attack: PathTraversal,
		inputs: traversalInputs(),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			dir := fileFixture(t)
			data, err := ReadFile(ctx, dir+"/sub/"+traversal)
			return string(data) == "kit", err
		},
	})
}

// Every helper refuses a traversal before touching the file system, and
// lets it through (reported once) in monitor mode.
func TestEveryFileHelper(t *testing.T) {
	type helper struct {
		name string
		// run uses p (a path holding the input); dir is the fixture.
		run func(ctx context.Context, dir, p string) error
		// done reports whether the operation happened.
		done func(dir string) bool
	}
	kit := func(dir string) string { return filepath.Join(dir, "kit.txt") }
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	closeF := func(f *os.File, err error) error {
		if err == nil {
			f.Close()
		}
		return err
	}
	opened := false
	helpers := []helper{
		{"Open", func(ctx context.Context, _, p string) error {
			err := closeF(Open(ctx, p))
			opened = err == nil
			return err
		},
			func(string) bool { return opened }},
		{"OpenFile read", func(ctx context.Context, _, p string) error {
			err := closeF(OpenFile(ctx, p, os.O_RDONLY, 0))
			opened = err == nil
			return err
		}, func(string) bool { return opened }},
		{"OpenFile write", func(ctx context.Context, _, p string) error {
			return closeF(OpenFile(ctx, p, os.O_WRONLY|os.O_TRUNC, 0o644))
		}, func(dir string) bool { b, _ := os.ReadFile(kit(dir)); return len(b) == 0 }},
		{"Create", func(ctx context.Context, _, p string) error { return closeF(Create(ctx, p)) },
			func(dir string) bool { b, _ := os.ReadFile(kit(dir)); return len(b) == 0 }},
		{"WriteFile", func(ctx context.Context, _, p string) error { return WriteFile(ctx, p, []byte("new"), 0o644) },
			func(dir string) bool { b, _ := os.ReadFile(kit(dir)); return string(b) == "new" }},
		{"Remove", func(ctx context.Context, _, p string) error { return Remove(ctx, p) },
			func(dir string) bool { return !exists(kit(dir)) }},
		{"RemoveAll", func(ctx context.Context, _, p string) error { return RemoveAll(ctx, p) },
			func(dir string) bool { return !exists(kit(dir)) }},
		{"Rename source", func(ctx context.Context, dir, p string) error {
			return Rename(ctx, p, filepath.Join(dir, "moved.txt"))
		}, func(dir string) bool { return exists(filepath.Join(dir, "moved.txt")) }},
		{"Rename target", func(ctx context.Context, dir, _ string) error {
			if err := os.WriteFile(filepath.Join(dir, "src.txt"), []byte("s"), 0o644); err != nil {
				return err
			}
			return Rename(ctx, filepath.Join(dir, "src.txt"), dir+"/sub/"+traversal)
		}, func(dir string) bool { b, _ := os.ReadFile(kit(dir)); return string(b) == "s" }},
		{"ReadDir", func(ctx context.Context, dir, _ string) error {
			_, err := ReadDir(ctx, dir+"/sub/../sub")
			opened = err == nil
			return err
		}, func(string) bool { return opened }},
		{"CheckPath", func(ctx context.Context, _, p string) error { opened = true; return CheckPath(ctx, p, OpRead) },
			func(string) bool { return opened }},
	}
	for _, h := range helpers {
		t.Run(h.name, func(t *testing.T) {
			inputs := traversalInputs()
			if h.name == "ReadDir" {
				inputs = AddInput(nil, "../sub", "query.dir")
			}
			setupEngine(t, engineSettings{mode: ModeBlock})
			dir := fileFixture(t)
			opened = false
			err := h.run(requestCtx(inputs, nil), dir, dir+"/sub/"+traversal)
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("block: %v", err)
			}
			if h.name != "CheckPath" && h.done(dir) {
				t.Fatal("the operation happened although blocked")
			}

			log := setupEngine(t, engineSettings{mode: ModeMonitor})
			dir = fileFixture(t)
			opened = false
			if err := h.run(requestCtx(inputs, nil), dir, dir+"/sub/"+traversal); err != nil {
				t.Fatalf("monitor: %v", err)
			}
			if !h.done(dir) {
				t.Fatal("the operation did not happen in monitor mode")
			}
			if ev := eventsOf(log, PathTraversal); len(ev) != 1 {
				t.Fatalf("want one event, got %v", log.all())
			}
		})
	}
}

func TestFileRules(t *testing.T) {
	t.Run("script write during a request", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		dir := t.TempDir()
		ctx := requestCtx(AddInput(nil, "shell.php", "body.name"), nil)
		err := WriteFile(ctx, filepath.Join(dir, "shell.php"), []byte("<?php"), 0o644)
		if b := AsBlocked(err); b == nil || b.Rule != "file_write.script" {
			t.Fatalf("got %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "shell.php")); err == nil {
			t.Fatal("written")
		}
	})
	t.Run("outside the file roots", func(t *testing.T) {
		dir := fileFixture(t)
		setupEngine(t, engineSettings{mode: ModeBlock, allow: Allow{FileRoots: []string{filepath.Join(dir, "sub")}}})
		ctx := requestCtx(AddInput(nil, "kit.txt", "query.f"), nil)
		if _, err := ReadFile(ctx, filepath.Join(dir, "kit.txt")); AsBlocked(err) == nil || AsBlocked(err).Rule != "path.outside_root" {
			t.Fatalf("got %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sub", "kit.txt"), []byte("in"), 0o644); err != nil {
			t.Fatal(err)
		}
		if b, err := ReadFile(ctx, filepath.Join(dir, "sub", "kit.txt")); err != nil || string(b) != "in" {
			t.Fatalf("inside the root: %v", err)
		}
	})
	t.Run("NTFS stream with no RASP context", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		p := filepath.Join(t.TempDir(), "a.txt::$DATA")
		if err := WriteFile(context.Background(), p, nil, 0o644); AsBlocked(err) == nil {
			t.Fatalf("got %v", err)
		}
		// Reads outside a context pass untouched.
		dir := fileFixture(t)
		if _, err := ReadFile(context.Background(), dir+"/sub/"+traversal); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("open flags", func(t *testing.T) {
		cases := map[int]FileOp{
			os.O_RDONLY: OpRead, os.O_WRONLY: OpWrite, os.O_RDWR | os.O_CREATE: OpWrite,
			os.O_WRONLY | os.O_APPEND: OpAppend, os.O_WRONLY | os.O_APPEND | os.O_TRUNC: OpWrite,
		}
		for flag, want := range cases {
			if got := openFlagOp(flag); got != want {
				t.Errorf("flag %#x: %s, want %s", flag, got, want)
			}
		}
	})
}
