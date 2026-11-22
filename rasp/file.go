package rasp

import (
	"context"
	"os"
)

// File sink (README "Path"). The helpers are the os functions with a
// context first; each checks its path (both paths for Rename) for
// path_traversal and file_write before the call, with allow.fileRoots, and
// returns the block error instead of touching the file system:
//
//	data, err := rasp.ReadFile(r.Context(), filepath.Join(dir, name))
//
// Outside a RASP context (no request or scope in ctx) only file_write.ntfs
// applies, and the check costs no system call.

func checkPaths(ctx context.Context, sink string, ops ...pathOp) error {
	if !Active() {
		return nil
	}
	rc := FromContext(ctx)
	return checkSink(ctx, sink, func(slot *iastSlot) *Finding {
		if rc == nil {
			for _, o := range ops {
				if isWriteOp(o.op) && ntfsStream.MatchString(o.path) {
					return &Finding{Attack: FileWrite, Rule: "file_write.ntfs"}
				}
			}
			return nil
		}
		inputs, inRequest, roots := rc.Inputs(), rc.InRequest(), AllowLists().FileRoots
		// Every path is checked; the strongest decision wins.
		found := make([]*Finding, len(ops))
		for i, o := range ops {
			found[i] = detectPathWith(o.path, o.op, inputs, roots, inRequest, slot)
		}
		return Strongest(found...)
	})
}

type pathOp struct {
	path string
	op   FileOp
}

func isWriteOp(op FileOp) bool {
	return op == OpWrite || op == OpAppend || op == OpRename || op == OpOpen
}

// openFlagOp is the kind of access an os.OpenFile flag asks for.
func openFlagOp(flag int) FileOp {
	switch {
	case flag&os.O_APPEND != 0 && flag&os.O_TRUNC == 0:
		return OpAppend
	case flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0:
		return OpWrite
	}
	return OpRead
}

// CheckPath checks a path about to be used some other way (os.Root, a
// library that opens files itself). It returns only the block error.
func CheckPath(ctx context.Context, path string, op FileOp) error {
	return checkPaths(ctx, "file.access", pathOp{path, op})
}

// Open is os.Open with RASP checks (a read).
func Open(ctx context.Context, name string) (*os.File, error) {
	if err := checkPaths(ctx, "os.Open", pathOp{name, OpRead}); err != nil {
		return nil, err
	}
	return os.Open(name)
}

// Create is os.Create with RASP checks (a write).
func Create(ctx context.Context, name string) (*os.File, error) {
	if err := checkPaths(ctx, "os.Create", pathOp{name, OpWrite}); err != nil {
		return nil, err
	}
	if err := checkBackdoorWrite(ctx, "os.Create", name, "", nil); err != nil {
		return nil, err
	}
	return os.Create(name)
}

// OpenFile is os.OpenFile with RASP checks; the flag decides whether it is
// a read, a write or an append.
func OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (*os.File, error) {
	op := openFlagOp(flag)
	if err := checkPaths(ctx, "os.OpenFile", pathOp{name, op}); err != nil {
		return nil, err
	}
	if isWriteOp(op) {
		if err := checkBackdoorWrite(ctx, "os.OpenFile", name, "", nil); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(name, flag, perm)
}

// ReadFile is os.ReadFile with RASP checks.
func ReadFile(ctx context.Context, name string) ([]byte, error) {
	if err := checkPaths(ctx, "os.ReadFile", pathOp{name, OpRead}); err != nil {
		return nil, err
	}
	return os.ReadFile(name)
}

// WriteFile is os.WriteFile with RASP checks.
func WriteFile(ctx context.Context, name string, data []byte, perm os.FileMode) error {
	if err := checkPaths(ctx, "os.WriteFile", pathOp{name, OpWrite}); err != nil {
		return err
	}
	if err := checkBackdoorWrite(ctx, "os.WriteFile", name, "", data); err != nil {
		return err
	}
	return os.WriteFile(name, data, perm)
}

// Remove is os.Remove with RASP checks.
func Remove(ctx context.Context, name string) error {
	if err := checkPaths(ctx, "os.Remove", pathOp{name, OpDelete}); err != nil {
		return err
	}
	return os.Remove(name)
}

// RemoveAll is os.RemoveAll with RASP checks.
func RemoveAll(ctx context.Context, path string) error {
	if err := checkPaths(ctx, "os.RemoveAll", pathOp{path, OpDelete}); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// Rename is os.Rename with RASP checks on both paths.
func Rename(ctx context.Context, oldpath, newpath string) error {
	if err := checkPaths(ctx, "os.Rename", pathOp{oldpath, OpRename}, pathOp{newpath, OpRename}); err != nil {
		return err
	}
	if err := checkBackdoorWrite(ctx, "os.Rename", newpath, oldpath, nil); err != nil {
		return err
	}
	return os.Rename(oldpath, newpath)
}

// ReadDir is os.ReadDir with RASP checks (a listing).
func ReadDir(ctx context.Context, name string) ([]os.DirEntry, error) {
	if err := checkPaths(ctx, "os.ReadDir", pathOp{name, OpList}); err != nil {
		return nil, err
	}
	return os.ReadDir(name)
}
