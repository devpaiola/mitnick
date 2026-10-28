package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitnick-security/mitnick/internal/config"
	"github.com/mitnick-security/mitnick/internal/reporter"
)

func TestScanFlagsAfterPathWriteSanitizedJSON(t *testing.T) {
	root := t.TempDir()
	keyValue := strings.Join([]string{"AKIAIOSFODNN7", "EXAMPLE"}, "")
	if err := os.WriteFile(filepath.Join(root, "credentials.txt"), []byte("key="+keyValue), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"scan", root, "--format", "json", "--fail-on", "none"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("scan returned error: %v, stderr=%s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), keyValue) {
		t.Fatal("report leaked the secret")
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report["schema_version"] != "1.0" {
		t.Fatalf("unexpected schema: %#v", report["schema_version"])
	}
}

func TestGitleaksRequiresExplicitScanOptIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script engine fixture is not portable to Windows")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("const safe = true;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "engine-ran")
	binary := filepath.Join(binDir, "gitleaks")
	script := "#!/bin/sh\n: > " + shellQuote(marker) + "\nreport=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--report-path\" ]; then report=\"$2\"; shift 2; else shift; fi\ndone\nprintf '[]' > \"$report\"\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"scan", root, "--format", "json", "--fail-on", "none"}, &stdout, &stderr); err != nil {
		t.Fatalf("default scan failed: %v; stderr=%s", err, stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("default scan invoked Gitleaks without opt-in")
	}
	stdout.Reset()
	stderr.Reset()
	if err := Run(context.Background(), []string{"scan", root, "--gitleaks", "--format", "json", "--fail-on", "none"}, &stdout, &stderr); err != nil {
		t.Fatalf("opt-in Gitleaks scan failed: %v; stderr=%s", err, stderr.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("--gitleaks did not invoke the external engine: %v", err)
	}
}

func TestScanAIRequiresConnectedCLIAndOneScanConsent(t *testing.T) {
	root := t.TempDir()
	setIsolatedUserConfigHome(t)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"scan", root, "--ai"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "nenhuma IA conectada") {
		t.Fatalf("scan without a selected CLI returned %v", err)
	}
	if _, err := config.WriteAIProfile(config.AIConfig{Provider: "codex"}); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), []string{"scan", root, "--ai"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--ai-consent") {
		t.Fatalf("scan without consent returned %v", err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func setIsolatedUserConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func TestExitCodesSeparateFindingsFromErrors(t *testing.T) {
	if got := ExitCode(findingsError{}); got != 1 {
		t.Fatalf("finding exit code %d", got)
	}
	if got := ExitCode(scanFailureError{message: "engine"}); got != 3 {
		t.Fatalf("operational failure exit code %d, want 3", got)
	}
	if got := ExitCode(nil); got != 0 {
		t.Fatalf("success exit code %d", got)
	}
	if got := ExitCode(context.Canceled); got != 130 {
		t.Fatalf("cancellation exit code %d, want 130", got)
	}
	if got := ExitCode(context.DeadlineExceeded); got != 3 {
		t.Fatalf("deadline exit code %d, want 3", got)
	}
}

func TestNoArgumentsPrintHelpOutsideInteractiveTerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), nil, &stdout, &stderr); err != nil {
		t.Fatalf("noninteractive invocation should print help: %v", err)
	}
	if !strings.Contains(stdout.String(), "mitnick menu") || !strings.Contains(stdout.String(), "mitnick ai") {
		t.Fatalf("help omitted the TUI or AI commands: %s", stdout.String())
	}
}

func TestAIConnectPersistsCLIAndDetectDoesNotExecuteCLIs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH marker fixture uses a shell script")
	}
	setIsolatedUserConfigHome(t)
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "provider-executed")
	for _, name := range []string{"codex", "claude"} {
		binary := filepath.Join(binDir, name)
		script := "#!/bin/sh\n: > " + shellQuote(marker) + "\nexit 0\n"
		if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"ai", "detect"}, &stdout, &stderr); err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Codex CLI") || !strings.Contains(stdout.String(), "Claude Code") || !strings.Contains(stdout.String(), "disponível") {
		t.Fatalf("client inventory is incomplete: %s", stdout.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("CLI discovery executed a client")
	}
	if err := Run(context.Background(), []string{"ai", "connect", "codex"}, &stdout, &stderr); err != nil {
		t.Fatalf("connect failed: %v; stderr=%s", err, stderr.String())
	}
	profilePath, err := config.DefaultAIProfilePath()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := os.ReadFile(profilePath)
	if err != nil || strings.Contains(string(profile), "api_key") {
		t.Fatalf("user profile is missing or stores credentials: %s (%v)", profile, err)
	}
	aiProfile, _, found, err := config.ReadAIProfile(profilePath)
	if err != nil || !found || aiProfile.Provider != "codex" {
		t.Fatalf("profile did not persist connected CLI: %#v (%v)", aiProfile, err)
	}
}

func TestAITestRunsContentFreePromptThroughSelectedCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a shell script")
	}
	setIsolatedUserConfigHome(t)
	if _, err := config.WriteAIProfile(config.AIConfig{Provider: "codex"}); err != nil {
		t.Fatal(err)
	}
	binDir, markerDir := t.TempDir(), t.TempDir()
	script := `#!/bin/sh
cat > "$MITNICK_TEST_INPUT"
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then shift; out="$1"; fi
  shift
done
printf '%s' '{"observations":[]}' > "$out"
`
	if err := os.WriteFile(filepath.Join(binDir, "codex"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MITNICK_TEST_INPUT", filepath.Join(markerDir, "input"))
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"ai", "test"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("content-free CLI test failed: %v", err)
	}
	input, err := os.ReadFile(filepath.Join(markerDir, "input"))
	if err != nil || !strings.Contains(string(input), "teste de conexão sem analisar projeto") || strings.Contains(string(input), "project source") {
		t.Fatalf("unexpected test prompt: %q (%v)", input, err)
	}
	if !strings.Contains(stdout.String(), "nenhum conteúdo do projeto foi enviado") {
		t.Fatalf("test command did not explain its input: %s", stdout.String())
	}
}

func TestInvalidReportFormatDoesNotTruncateDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("keep this report"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeReport("unknown", path, &bytes.Buffer{}, reporter.JSONReport{})
	if err == nil {
		t.Fatal("unsupported report format was accepted")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "keep this report" {
		t.Fatalf("invalid format modified existing report: %q", got)
	}
}

func TestReportOutputRemainsPrivateAndPropagatesWriteErrors(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeReport("json", existing, &bytes.Buffer{}, reporter.JSONReport{}); err == nil || !strings.Contains(err.Error(), "não sobrescreve") {
		t.Fatalf("existing report should not be overwritten: %v", err)
	}
	got, err := os.ReadFile(existing)
	if err != nil || string(got) != "old" {
		t.Fatalf("existing report changed: %q (%v)", got, err)
	}
	path := filepath.Join(dir, "new.json")
	if err := writeReport("json", path, &bytes.Buffer{}, reporter.JSONReport{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("report permissions = %o, want 600", info.Mode().Perm())
	}
	if err := writeReport("json", "", errorWriter{}, reporter.JSONReport{}); err == nil {
		t.Fatal("report write error was discarded")
	}
}

func TestScanReportDestinationMustBeOutsideProject(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if _, err := safeScanOutputPath(root, filepath.Join(root, "report.json")); err == nil {
		t.Fatal("report path inside analyzed project was accepted")
	}
	if _, err := safeScanOutputPath(root, filepath.Join(outside, "report.json")); err != nil {
		t.Fatalf("outside report path rejected: %v", err)
	}
	link := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := safeScanOutputPath(root, filepath.Join(link, "report.json")); err == nil {
		t.Fatal("symlinked destination inside project was accepted")
	}
}

func TestScanLeavesProjectByteForByteUnchangedAndExportsOutside(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"src/app.js": `eval(input);`,
		".mcp.json":  `{"servers":{}}`,
		"AGENTS.md":  "review this repository",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotProject(t, root)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"scan", root, "--format", "json", "--fail-on", "none"}, &stdout, &stderr); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	assertProjectSnapshot(t, root, before)

	inside := filepath.Join(root, "scan-report.json")
	stdout.Reset()
	if err := Run(context.Background(), []string{"scan", root, "--format", "json", "--output", inside, "--fail-on", "none"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "fora do projeto") {
		t.Fatalf("report inside project should be rejected: %v", err)
	}
	assertProjectSnapshot(t, root, before)

	outside := filepath.Join(t.TempDir(), "scan-report.json")
	if err := Run(context.Background(), []string{"scan", root, "--format", "json", "--output", outside, "--fail-on", "none"}, &stdout, &stderr); err != nil {
		t.Fatalf("outside report failed: %v", err)
	}
	assertProjectSnapshot(t, root, before)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("report was not created: %v", err)
	}
}

func snapshotProject(t *testing.T, root string) map[string][]byte {
	t.Helper()
	items := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		items[rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func assertProjectSnapshot(t *testing.T, root string, before map[string][]byte) {
	t.Helper()
	after := snapshotProject(t, root)
	if len(after) != len(before) {
		t.Fatalf("scan changed project file count from %d to %d", len(before), len(after))
	}
	for path, original := range before {
		if !bytes.Equal(after[path], original) {
			t.Fatalf("scan modified project file %s", path)
		}
	}
}

func TestAIOptInWithoutConnectedCLIStopsBeforeScanning(t *testing.T) {
	setIsolatedUserConfigHome(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("eval(input);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"scan", root, "--ai", "--format", "json", "--fail-on", "none"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "nenhuma IA conectada") {
		t.Fatalf("scan without a connected CLI returned %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("scan should stop before output or model calls: %s", stdout.String())
	}
}

func TestReportOutputRejectsSymlinks(t *testing.T) {
	target := filepath.Join(t.TempDir(), "sensitive.json")
	if err := os.WriteFile(target, []byte("leave unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "report.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := writeReport("json", link, &bytes.Buffer{}, reporter.JSONReport{}); err == nil {
		t.Fatal("report output followed a symbolic link")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "leave unchanged" {
		t.Fatalf("symlink destination changed target: %q", got)
	}
}

func TestScanTimeoutCannotExceedConfiguredMaximum(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"scan", root, "--timeout", "2h"}, &stdout, &stderr)
	if ExitCode(err) != 2 || err == nil || !strings.Contains(err.Error(), "não maior que 1h") {
		t.Fatalf("oversized scan timeout was not rejected: %v", err)
	}
}

func TestReportInputIsBoundedAndMustBeRegular(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(path, 4); err == nil || !strings.Contains(err.Error(), "limite") {
		t.Fatalf("oversized report was not rejected: %v", err)
	}
	if _, err := readBoundedFile(t.TempDir(), 4); err == nil || !strings.Contains(err.Error(), "arquivo regular") {
		t.Fatalf("directory was accepted as a report: %v", err)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestThresholdStatusKeepsJSONReportValid(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("eval(input);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		threshold string
		wantCode  int
	}{{"high", 0}, {"medium", 1}} {
		t.Run(tc.threshold, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run(context.Background(), []string{"scan", root, "--format", "json", "--fail-on", tc.threshold}, &stdout, &stderr)
			if got := ExitCode(err); got != tc.wantCode {
				t.Fatalf("threshold %s produced exit code %d (%v), want %d", tc.threshold, got, err, tc.wantCode)
			}
			var report map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("threshold failure did not preserve valid JSON output: %v (%s)", err, stdout.String())
			}
			if len(report["findings"].([]any)) != 1 {
				t.Fatalf("report should retain its finding: %#v", report["findings"])
			}
		})
	}
}

func TestScanErrorStillWritesValidJSONAndFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"scan", missing, "--format", "json", "--fail-on", "none"}, &stdout, &stderr)
	if ExitCode(err) != 3 {
		t.Fatalf("expected scan failure exit code, got %v", err)
	}
	var report map[string]any
	if parseErr := json.Unmarshal(stdout.Bytes(), &report); parseErr != nil {
		t.Fatalf("error report is not valid JSON: %v (%s)", parseErr, stdout.String())
	}
	if len(report["engine_errors"].([]any)) == 0 {
		t.Fatal("missing discovery failure in report")
	}
}

func TestDoctorDoesNotProbeConfiguredAIWithoutOptIn(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"doctor"}, &stdout, &stderr); err != nil {
		t.Fatalf("doctor tried to connect without --ai-check: %v", err)
	}
	if !strings.Contains(stdout.String(), "Rede: nenhuma chamada realizada") {
		t.Fatalf("doctor did not report no network call: %s", stdout.String())
	}
	for _, want := range []string{"2026-10-25", "lodash, axios, next, React Server Components e minimist", "docs/advisory-snapshot.md"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("doctor did not describe advisory coverage (%q): %s", want, stdout.String())
		}
	}
}

func TestRulesListIncludesAdvisorySnapshotFamilies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"rules", "list"}, &stdout, &stderr); err != nil {
		t.Fatalf("rules list failed: %v", err)
	}
	for _, id := range []string{
		"GITLEAKS-*",
		"GHSA-xxjr-mmjv-4gpg",
		"GHSA-x97p-jq2g-jp4f",
		"GHSA-mcj8-r9mp-w47p",
		"GHSA-fv66-9v8q-g76r",
		"GHSA-wx67-qw84-cm4g",
		"GHSA-xvch-5gv4-984h",
	} {
		if !strings.Contains(stdout.String(), id) {
			t.Errorf("rules list omitted %s: %s", id, stdout.String())
		}
	}
}

func TestIntelUpdateRejectsIgnoredIdentifierFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "OSV", args: []string{"intel", "update", t.TempDir(), "--source", "osv", "--id", "CVE-2025-1234"}},
		{name: "CWE", args: []string{"intel", "update", "--source", "mitre-cwe", "--id", "CVE-2025-1234"}},
		{name: "KEV", args: []string{"intel", "update", "--source", "cisa-kev", "--id", "CVE-2025-1234"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := Run(context.Background(), tc.args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), "--id não se aplica") {
				t.Fatalf("ignored --id was accepted: %v", err)
			}
		})
	}
}

func TestScanWithoutAIDoesNotCallConfiguredProvider(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a shell script")
	}
	setIsolatedUserConfigHome(t)
	if _, err := config.WriteAIProfile(config.AIConfig{Provider: "codex"}); err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "called")
	script := "#!/bin/sh\n: > " + shellQuote(marker) + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "codex"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("const safe = true;"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"scan", root, "--format", "json", "--fail-on", "none"}, &stdout, &stderr); err != nil {
		t.Fatalf("scan attempted the configured provider or failed: %v (%s)", err, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if _, ok := report["ai"]; ok {
		t.Fatal("disabled AI appeared in report metadata")
	}
	if errs, ok := report["engine_errors"].([]any); ok && len(errs) != 0 {
		t.Fatalf("disabled AI generated engine errors: %#v", errs)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("scan without --ai invoked connected Codex")
	}
}
