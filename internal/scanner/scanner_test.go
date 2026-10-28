package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverSkipsSymlinksAndDefaultDirectories(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "safe.txt"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("must not read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "ignored.js"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover(root, DiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "safe.txt" {
		t.Fatalf("unexpected discovered files: %#v", result.Files)
	}
	if result.Skipped < 2 {
		t.Fatalf("expected symlink and directory skips, got %d", result.Skipped)
	}
}

func TestDiscoverIncludeNamesReadsOnlyAllowlistedBasenames(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "app.go"), []byte("source-secret-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover(root, DiscoveryOptions{IncludeNames: []string{"package-lock.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "package-lock.json" {
		t.Fatalf("discovery read non-allowlisted content: %#v", result.Files)
	}
	if strings.Contains(string(result.Files[0].Content), "source-secret-marker") {
		t.Fatal("non-allowlisted source content was read")
	}
	if len(result.Paths) != 2 || result.Paths[0] != "package-lock.json" || result.Paths[1] != "src/app.go" {
		t.Fatalf("candidate path inventory missing: %#v", result.Paths)
	}
}

func TestDiscoverRejectsNonBasenameIncludeNames(t *testing.T) {
	if _, err := Discover(t.TempDir(), DiscoveryOptions{IncludeNames: []string{"src/package-lock.json"}}); err == nil {
		t.Fatal("include name with a path was accepted")
	}
}

func TestDiscoverHonorsIgnoreAndSizeLimits(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mitnickignore"), []byte("ignored/**\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "ignored"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ignored", "file.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover(root, DiscoveryOptions{MaxBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("expected ignore file and source file, got %#v", result.Files)
	}
	if _, err := Discover(root, DiscoveryOptions{MaxBytes: 2}); err == nil {
		t.Fatal("expected total byte limit to fail")
	}
}

func TestDiscoverSkipsFilesAbovePerFileLimit(t *testing.T) {
	root := t.TempDir()
	large := make([]byte, MaxFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "large.js"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "small.js"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover(root, DiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "small.js" || result.Skipped != 1 || len(result.Warnings) == 0 {
		t.Fatalf("unexpected result for oversized file: %#v", result)
	}
}

func TestDiscoverPreservesUnicodePath(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "ação", "arquivo.ts")
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("export const ok = true;"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover(root, DiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "ação/arquivo.ts" {
		t.Fatalf("Unicode path changed during discovery: %#v", result.Files)
	}
}

func TestDiscoverDoesNotReadIgnoreFileSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "ignore-rules")
	if err := os.WriteFile(outside, []byte("visible/**\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".mitnickignore")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "visible"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible", "app.js"), []byte("keep scanning"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Discover(root, DiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "visible/app.js" {
		t.Fatalf("ignore-file symlink affected discovery: %#v", result.Files)
	}
	if len(result.Warnings) == 0 {
		t.Fatal("ignored ignore-file symlink was not reported")
	}
}

func TestDiscoverAcceptsSymlinkAsScanRootWithoutFollowingInnerLinks(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.js"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "project")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result, err := Discover(alias, DiscoveryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "app.js" {
		t.Fatalf("symlinked scan root was not traversed safely: %#v", result.Files)
	}
}

func TestDiscoverEnforcesEntryLimitAndCancellation(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "file.js"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(root, DiscoveryOptions{MaxEntries: 2}); err == nil {
		t.Fatal("expected directory entries to be counted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DiscoverContext(ctx, root, DiscoveryOptions{}); err == nil {
		t.Fatal("expected canceled discovery to stop before walking")
	}
}

func TestExclusionPatternsAreBoundedAndValidated(t *testing.T) {
	for _, tc := range []struct {
		name     string
		patterns []string
		dirs     []string
	}{
		{"invalid glob", []string{"src/["}, nil},
		{"parent traversal", []string{"../**"}, nil},
		{"overlong pattern", []string{string(make([]byte, MaxExcludePatternBytes+1))}, nil},
		{"nonportable separator", []string{`src\\**`}, nil},
		{"directory path", nil, []string{"src/generated"}},
		{"too many patterns", make([]string, MaxExcludePatterns+1), nil},
		{"too many dirs", nil, make([]string, MaxExcludeDirs+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateExclusions(tc.patterns, tc.dirs); err == nil {
				t.Fatal("invalid exclusion configuration was accepted")
			}
		})
	}
	if err := ValidateExclusions([]string{"**/*.go", "vendor/**"}, []string{"generated", "node_modules"}); err != nil {
		t.Fatalf("valid exclusion patterns were rejected: %v", err)
	}
}

func TestGlobPathSupportsGlobstarWithoutRecursiveMatcherState(t *testing.T) {
	for _, tc := range []struct {
		pattern, target string
		want            bool
	}{
		{"**/*.js", "src/app.js", true},
		{"**/*.js", "app.ts", false},
		{"src/**/app.js", "src/app.js", true},
		{"src/**/app.js", "src/nested/app.js", true},
		{"src/*.js", "src/nested/app.js", false},
		{"[ab].js", "a.js", true},
	} {
		if got := globPath(tc.pattern, tc.target); got != tc.want {
			t.Errorf("globPath(%q, %q) = %t, want %t", tc.pattern, tc.target, got, tc.want)
		}
	}
}

func FuzzValidateExclusionsAndGlobMatching(f *testing.F) {
	f.Add("**/*.js", "src/app.js")
	f.Add("src/[", "src/app.js")
	f.Add("generated/**", "generated/file.ts")
	f.Fuzz(func(t *testing.T, pattern, target string) {
		if len(pattern)+len(target) > 512 {
			t.Skip()
		}
		_ = ValidateExclusions([]string{pattern}, nil)
		_ = globPath(pattern, target)
	})
}

func TestIgnoreFileRejectsExcessiveAndMalformedPatterns(t *testing.T) {
	for _, content := range []string{
		"src/[\n",
		strings.Repeat("ignored/**\n", MaxExcludePatterns+1),
	} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, ".mitnickignore"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Discover(root, DiscoveryOptions{}); err == nil {
			t.Errorf("invalid ignore patterns were accepted: %d bytes", len(content))
		}
	}
}
