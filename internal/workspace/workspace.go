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
	dir string // as given
	// dir with symlinks resolved, for messages too: dir may be a
	// /proc/self/fd/N handed down by the caller, which tells the user nothing.
	realDir string
	root    *os.Root
}

// evalSymlinks is filepath.EvalSymlinks, a variable so that a test can swap
// the root's path right after it is resolved.
var evalSymlinks = filepath.EvalSymlinks

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
//
// dir itself is opened, not its resolved path: a caller can pin the root
// with /proc/self/fd/N, and resolving that gives back a path that may be
// swapped for a symlink before it is opened.
//
// The resolved path only matches absolute names (rel) and names the root in
// messages. For /proc/self/fd/N exactly it is the path of the directory
// opened (resolve). For any other spelling, /dev/fd/N included, or if the
// directory moves later, it may name another directory: absolute names under
// it are then mapped to the same relative path in the directory opened, and
// those under the directory's own path are refused, but nothing outside the
// directory opened is reached.
func Open(dir string) (*Root, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("root %q is not an absolute path", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	realDir, err := resolve(dir)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &Root{dir: filepath.Clean(dir), realDir: realDir, root: root}, nil
}

// resolve returns dir with its symlinks resolved. A /proc/self/fd/N is only
// read with Readlink: the kernel gives the path of the directory the fd has
// open, while EvalSymlinks would go on to walk that path, which may have been
// swapped for a symlink by then.
func resolve(dir string) (string, error) {
	// Cleaned, as a trailing slash would make Readlink follow the link.
	if dir = filepath.Clean(dir); filepath.Dir(dir) == "/proc/self/fd" {
		return os.Readlink(dir)
	}
	return evalSymlinks(dir)
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
		return "", fmt.Errorf("%s: outside %s", name, r.realDir)
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
