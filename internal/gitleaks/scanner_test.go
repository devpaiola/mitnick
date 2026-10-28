package gitleaks

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mitnick-security/mitnick/internal/scanner"
)

func TestGitleaksStagesOnlyDiscoveredFilesAndRedactsFindings(t *testing.T) {
	root, binary := scannerTestPaths(t)
	var workspace string
	engine := Scanner{Binary: binary, run: func(_ context.Context, _ string, args []string, directory string, environment []string) error {
		workspace = directory
		if !hasArgumentPair(args, "--no-git", "--source") || !hasArgument(args, "--redact") || !hasArgument(args, "--exit-code") {
			t.Fatalf("Gitleaks safety flags missing: %v", args)
		}
		if strings.Contains(strings.Join(environment, "\x00"), "AWS_SECRET_ACCESS_KEY") || strings.Contains(strings.Join(environment, "\x00"), "GITLEAKS_CONFIG") {
			t.Fatal("scanner environment leaked credentials or repository config selection")
		}
		source := argumentValue(args, "--source")
		content, err := os.ReadFile(filepath.Join(source, "src", "app.js"))
		if err != nil || string(content) != "unique-staged-content" {
			t.Fatalf("discovered file was not staged: %q, %v", content, err)
		}
		if _, err := os.Stat(filepath.Join(source, ".gitleaks.toml")); !os.IsNotExist(err) {
			t.Fatal("repository Gitleaks config was staged")
		}
		data, err := json.Marshal([]map[string]any{{
			"File": filepath.Join(source, "src", "app.js"), "RuleID": "generic-api-key",
			"StartLine": 3, "StartColumn": 2, "EndLine": 3, "EndColumn": 22, "Secret": "do-not-copy-this-secret",
		}})
		if err != nil {
			return err
		}
		return os.WriteFile(argumentValue(args, "--report-path"), data, 0o600)
	}}
	t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret-must-not-be-inherited")
	items, err := engine.Scan(context.Background(), root, []scanner.File{
		{Path: "src/app.js", Content: []byte("unique-staged-content")},
		{Path: ".gitleaks.toml", Content: []byte("[allowlist]\npaths = [\".*\"]")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d findings, want 1", len(items))
	}
	item := items[0]
	if item.RuleID != "GITLEAKS-generic-api-key" || item.Location.File != "src/app.js" || item.Location.Line != 3 || item.Location.Column != 2 {
		t.Fatalf("unexpected finding mapping: %#v", item)
	}
	if strings.Contains(item.Evidence, "do-not-copy-this-secret") || item.State != "suspected" || item.Origin != "gitleaks" {
		t.Fatalf("finding exposed data or lost provenance: %#v", item)
	}
	if _, err := os.Stat(workspace); !os.IsNotExist(err) {
		t.Fatal("temporary staged files were not removed")
	}
}

func TestGitleaksRejectsUnexpectedReportPathsAndMalformedJSON(t *testing.T) {
	root, binary := scannerTestPaths(t)
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"path outside scan", `[{"File":"../../outside","RuleID":"x","StartLine":1}]`, "localização fora"},
		{"duplicate key", `[{"File":"app.js","File":"app.js","RuleID":"x","StartLine":1}]`, "JSON ambíguo"},
		{"invalid JSON", `not-json`, "inválido"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := Scanner{Binary: binary, run: func(_ context.Context, _ string, args []string, _ string, _ []string) error {
				return os.WriteFile(argumentValue(args, "--report-path"), []byte(tc.data), 0o600)
			}}
			_, err := engine.Scan(context.Background(), root, []scanner.File{{Path: "app.js", Content: []byte("safe")}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestGitleaksBoundsStagingAndHidesProcessErrors(t *testing.T) {
	root, binary := scannerTestPaths(t)
	engine := Scanner{Binary: binary, run: func(context.Context, string, []string, string, []string) error {
		return errors.New("process output may contain a secret")
	}}
	_, err := engine.Scan(context.Background(), root, []scanner.File{{Path: "../../escape", Content: []byte("secret")}})
	if err == nil || !strings.Contains(err.Error(), "fora da pasta") {
		t.Fatalf("path traversal was not rejected before engine execution: %v", err)
	}
	_, err = engine.Scan(context.Background(), root, []scanner.File{{Path: "app.js", Content: []byte("safe")}})
	if err == nil || strings.Contains(err.Error(), "process output") {
		t.Fatalf("engine error leaked its raw output: %v", err)
	}
}

func TestGitleaksPropagatesCancellationDuringEngineRun(t *testing.T) {
	root, binary := scannerTestPaths(t)
	started := make(chan struct{})
	engine := Scanner{Binary: binary, run: func(ctx context.Context, _ string, _ []string, _ string, _ []string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := engine.Scan(ctx, root, []scanner.File{{Path: "app.js", Content: []byte("safe")}})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Gitleaks did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("engine cancellation was misreported: %v", err)
	}
}

func TestGitleaksPreservesParentScanDeadline(t *testing.T) {
	root, binary := scannerTestPaths(t)
	started := make(chan struct{})
	engine := Scanner{Binary: binary, run: func(ctx context.Context, _ string, _ []string, _ string, _ []string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := engine.Scan(ctx, root, []scanner.File{{Path: "app.js", Content: []byte("safe")}})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Gitleaks did not start")
	}
	err := <-done
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Gitleaks excedeu") {
		t.Fatalf("parent scan deadline was misreported: %v", err)
	}
}

func TestStageFilesHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := stageFiles(ctx, t.TempDir(), []scanner.File{{Path: "app.js", Content: []byte("safe")}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("staging ignored cancellation: %v", err)
	}
}

func FuzzGitleaksReport(f *testing.F) {
	f.Add(`[]`)
	f.Add(`[{"File":"app.js","RuleID":"generic-api-key","StartLine":1}]`)
	f.Add(`[{"File":"app.js","File":"app.js","StartLine":1}]`)
	f.Add(`[{"File":"../../outside","StartLine":1}]`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > scanner.MaxFileBytes {
			t.Skip()
		}
		_, _ = parseReport([]byte(input), filepath.Join("tmp", "stage"), map[string]bool{"app.js": true})
	})
}

func TestGitleaksRejectsEngineInsideScannedRoot(t *testing.T) {
	root, _ := scannerTestPaths(t)
	binary := filepath.Join(root, testBinaryName())
	if err := os.WriteFile(binary, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (Scanner{Binary: binary}).resolveBinary(root); err == nil || !strings.Contains(err.Error(), "fora da pasta") {
		t.Fatalf("engine from the scanned repository was accepted: %v", err)
	}
}

func scannerTestPaths(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(base, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, testBinaryName())
	if err := os.WriteFile(binary, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root, binary
}

func testBinaryName() string {
	if runtime.GOOS == "windows" {
		return "gitleaks.exe"
	}
	return "gitleaks"
}

func hasArgument(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}

func hasArgumentPair(args []string, first, second string) bool {
	return hasArgument(args, first) && hasArgument(args, second)
}

func argumentValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}
