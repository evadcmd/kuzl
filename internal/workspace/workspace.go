// Package workspace confines the files kuzl writes (-o) to one directory,
// KUZL_ROOT, or the working directory if it is unset.
//
// Where the root may be is up to whoever runs kuzl: taruza, for one, sets
// KUZL_ROOT to its own workspace directory. Commands take paths relative to
// the root, or absolute paths inside it.
//
// There is deliberately no way to read a file: kuzl never sends anything
// local, so a request can't carry a file out.
package workspace

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// EnvRoot names the root directory.
const EnvRoot = "KUZL_ROOT"

// Root is a directory files are written to. Nothing outside it can be
// reached, through ".." or symlinks alike (os.Root), and a symlink as the file
// itself is refused, so what is written is always a regular file in the root.
type Root struct {
	dir     string // as given, for messages
	realDir string // dir with symlinks resolved
	root    *os.Root
}

// FromEnv opens the root named by KUZL_ROOT, read with getenv, or the
// working directory if it is unset.
func FromEnv(getenv func(string) string) (*Root, error) {
	dir := getenv(EnvRoot)
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		dir = wd
	}
	return Open(dir)
}

// Open opens dir as a root. dir must be absolute.
func Open(dir string) (*Root, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("root %q is not an absolute path", dir)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(realDir)
	if err != nil {
		return nil, err
	}
	return &Root{dir: filepath.Clean(dir), realDir: realDir, root: root}, nil
}

// Close releases the root's directory handle.
func (r *Root) Close() error { return r.root.Close() }

// rel returns name relative to the root. name is relative to the root
// already, or absolute and inside it, spelled through the root as given or
// with its symlinks resolved.
func (r *Root) rel(name string) (string, error) {
	rel := name
	if filepath.IsAbs(name) {
		rel = ".."
		for _, dir := range []string{r.dir, r.realDir} {
			if s, err := filepath.Rel(dir, name); err == nil && filepath.IsLocal(s) {
				rel = s
				break
			}
		}
	}
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%s: outside %s", name, r.dir)
	}
	return filepath.Clean(rel), nil
}

// pathError names the file in err as the caller did. os.Root reports the
// path relative to the root, after the syscall, such as "statat x: no such
// file or directory", which isn't the path the caller gave.
func pathError(name string, err error) error {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		return fmt.Errorf("%s: %w", name, pe.Err)
	}
	return err
}

// Check reports whether name is inside the root, so that a command can refuse
// a path before it does anything else. It doesn't look at the file itself:
// Create does, when it opens it.
func (r *Root) Check(name string) error {
	_, err := r.rel(name)
	return err
}

// WriteFile writes data to name, as Create does.
func (r *Root) WriteFile(name string, data []byte) error {
	f, err := r.Create(name)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// Create opens name for writing, creating missing parent directories and
// emptying the file if it exists. A symlink at name is refused rather than
// followed. The caller closes the file.
func (r *Root) Create(name string) (*os.File, error) {
	rel, err := r.rel(name)
	if err != nil {
		return nil, err
	}
	if err := r.root.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		return nil, pathError(name, err)
	}
	info, err := r.root.Lstat(rel)
	var f *os.File
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// O_EXCL never follows a symlink, even one made since Lstat.
		f, err = r.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	case err != nil:
		return nil, pathError(name, err)
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s: not a regular file", name)
	default:
		// Truncated only once it is known to be the file Lstat saw.
		f, err = r.root.OpenFile(rel, os.O_WRONLY, 0)
	}
	if err != nil {
		return nil, pathError(name, err)
	}
	if info != nil {
		// OpenFile follows a symlink, so make sure it is still the file
		// Lstat saw.
		if opened, err := f.Stat(); err != nil || !os.SameFile(info, opened) {
			_ = f.Close()
			return nil, fmt.Errorf("%s: changed while being opened", name)
		}
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}
