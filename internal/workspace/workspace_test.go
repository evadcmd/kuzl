package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setup makes base/user as a root with a file in it, and a secret file next
// to base, outside the root.
func setup(t *testing.T) (r *Root, base, dir, secret string) {
	t.Helper()
	tmp := t.TempDir()
	base = filepath.Join(tmp, "workspace")
	dir = filepath.Join(base, "user")
	secret = filepath.Join(tmp, "secret.pem")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(dir, "sub", "body.md"): "hello",
		secret:                               "key",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, base, dir, secret
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Errorf("err = %v, want it to contain %q", err, substr)
	}
}

// wantFile checks that path holds content.
func wantFile(t *testing.T, path, content string) {
	t.Helper()
	if got, err := os.ReadFile(path); err != nil || string(got) != content { //nolint:gosec // G304: a path under the test temp dir.
		t.Errorf("%s = %q, %v; want %q", path, got, err, content)
	}
}

func TestOpen(t *testing.T) {
	_, base, dir, _ := setup(t)

	for _, d := range []string{base, dir} {
		r, err := Open(d)
		if err != nil {
			t.Errorf("Open(%q) = %v, want ok", d, err)
			continue
		}
		_ = r.Close()
	}
	_, err := Open("workspace/user")
	wantErr(t, err, "not an absolute path")
	_, err = Open(filepath.Join(base, "missing"))
	wantErr(t, err, "no such file")
}

func TestFromEnv(t *testing.T) {
	_, _, dir, _ := setup(t)
	write := func(content string, r *Root, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		if err := r.WriteFile("out.txt", []byte(content)); err != nil {
			t.Fatal(err)
		}
		wantFile(t, filepath.Join(dir, "out.txt"), content)
	}

	r, err := FromEnv(func(string) string { return dir })
	write("env", r, err)
	// Unset, it falls back to the working directory.
	t.Chdir(dir)
	r, err = FromEnv(func(string) string { return "" })
	write("wd", r, err)

	_, err = FromEnv(func(string) string { return "user" })
	wantErr(t, err, "not an absolute path")
}

func TestSymlinkedRootTakesBothSpellings(t *testing.T) {
	_, base, dir, _ := setup(t)
	link := filepath.Join(base, "link")
	symlink(t, dir, link)
	r, err := Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	for _, name := range []string{filepath.Join(link, "sub", "out.txt"), filepath.Join(dir, "sub", "out.txt")} {
		if err := r.WriteFile(name, []byte(name)); err != nil {
			t.Errorf("WriteFile(%q) = %v, want ok", name, err)
			continue
		}
		wantFile(t, filepath.Join(dir, "sub", "out.txt"), name)
	}
	wantErr(t, r.WriteFile(filepath.Join(base, "other.md"), []byte("x")), "outside "+link)
}

func TestCheck(t *testing.T) {
	r, _, dir, secret := setup(t)
	// Only the path counts: a file that doesn't exist yet is fine.
	for _, name := range []string{"new/out.txt", filepath.Join(dir, "sub", "body.md")} {
		if err := r.Check(name); err != nil {
			t.Errorf("Check(%q) = %v, want ok", name, err)
		}
	}
	for _, name := range []string{"../out.txt", secret, ""} {
		wantErr(t, r.Check(name), "outside")
	}
}

// Create streams into the file, which is emptied first, as WriteFile does.
func TestCreate(t *testing.T) {
	r, _, dir, secret := setup(t)
	symlink(t, secret, filepath.Join(dir, "link.pem"))

	f, err := r.Create("sub/body.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"a", "b"} {
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(dir, "sub", "body.md"), "ab")
	_, err = r.Create("link.pem")
	wantErr(t, err, "not a regular file")
	wantFile(t, secret, "key")
}

func TestWriteFile(t *testing.T) {
	r, _, dir, secret := setup(t)
	symlink(t, secret, filepath.Join(dir, "link.pem"))
	symlink(t, filepath.Dir(secret), filepath.Join(dir, "updir"))
	symlink(t, "sub", filepath.Join(dir, "inner"))

	if err := r.WriteFile("new/deep/out.txt", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile(filepath.Join(dir, "new", "deep", "out.txt"), []byte("two")); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(dir, "new", "deep", "out.txt"), "two")
	// A shorter write replaces the whole file, not just its start.
	if err := r.WriteFile("sub/body.md", []byte("hi")); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(dir, "sub", "body.md"), "hi")
	// A symlinked directory inside the root is fine; only escaping isn't.
	if err := r.WriteFile("inner/body.md", []byte("inner")); err != nil {
		t.Errorf("WriteFile through an inner symlinked dir = %v, want ok", err)
	}
	wantFile(t, filepath.Join(dir, "sub", "body.md"), "inner")

	tests := []struct{ name, want string }{
		{"../out.txt", "outside"},
		{secret, "outside"},
		{"", "outside"},
		{"link.pem", "not a regular file"},
		{"updir/out.txt", "escapes"},
		{"sub", "not a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantErr(t, r.WriteFile(tt.name, []byte("x")), tt.want)
		})
	}
	// Errors name the path as the caller gave it, here with a regular file
	// where a parent directory should be. The error itself is os.Root's
	// (EEXIST, from mkdirat on sub/body.md), so only the name is checked.
	name := filepath.Join(dir, "sub", "body.md", "out.txt")
	if err := r.WriteFile(name, []byte("x")); err == nil || !strings.HasPrefix(err.Error(), name+": ") {
		t.Errorf("err = %v, want it to start with %q", err, name+": ")
	}
	wantFile(t, secret, "key")
	if _, err := os.Stat(filepath.Join(filepath.Dir(secret), "out.txt")); err == nil {
		t.Error("a file was written outside the root")
	}
}
