package ai

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

func TestReviewRequiresPerScanConsentBeforeStartingCLI(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "called")
	writeFakeCLI(t, binDir, Codex, `#!/bin/sh
printf called > "$MITNICK_MARKER"
exit 0
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MITNICK_MARKER", marker)
	_, err := Review(context.Background(), Options{Provider: Codex}, []findings.Finding{{ID: "mitnick/web002", Fingerprint: "fp"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "--ai-consent") {
		t.Fatalf("Review error = %v; want consent requirement", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("CLI ran before content consent")
	}
}

func TestCodexReviewUsesIsolatedCWDStdinAndDisabledTools(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a shell script")
	}
	binDir := t.TempDir()
	markerDir := t.TempDir()
	response := `{"observations":[{"finding_id":"mitnick/web002","finding_fingerprint":"fp-1","analysis_type":"contextual_review","assessment":"inconclusive","summary":"A evidência precisa de revisão manual.","evidence_refs":["finding:fp-1"],"cwe_ids":["CWE-89"],"confidence":"low","limitations":["Análise consultiva."],"references":["https://cwe.mitre.org/data/definitions/89.html"]}]}`
	script := `#!/bin/sh
printf '%s\n' "$@" > "$MITNICK_ARGS"
printf '%s' "$PWD" > "$MITNICK_CWD"
cat > "$MITNICK_INPUT"
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then shift; out="$1"; fi
  shift
done
printf '%s' "$MITNICK_RESPONSE" > "$out"
`
	writeFakeCLI(t, binDir, Codex, script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MITNICK_ARGS", filepath.Join(markerDir, "args"))
	t.Setenv("MITNICK_CWD", filepath.Join(markerDir, "cwd"))
	t.Setenv("MITNICK_INPUT", filepath.Join(markerDir, "input"))
	t.Setenv("MITNICK_RESPONSE", response)
	root := t.TempDir()
	fileName := filepath.Join(root, "src", "handler.js")
	finding := findings.Finding{
		ID: "mitnick/web002", RuleID: "WEB002", Fingerprint: "fp-1", Domain: "code",
		Severity: "medium", Confidence: "medium", State: "suspected",
		Location: findings.Location{File: fileName, Line: 2}, CWEIDs: []string{"CWE-89"},
		References: []string{"https://cwe.mitre.org/data/definitions/89.html"},
	}
	files := []scanner.File{{Path: fileName, Content: []byte("const value = 1;\nconst result = query(input);\n")}}
	reviews, err := Review(context.Background(), Options{Provider: Codex, ContentConsent: true}, []findings.Finding{finding}, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviews) != 1 || reviews[0].FindingID != finding.ID {
		t.Fatalf("unexpected review: %#v", reviews)
	}
	stdin, err := os.ReadFile(filepath.Join(markerDir, "input"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stdin), root) || !strings.Contains(string(stdin), "const result = query(input)") {
		t.Fatalf("stdin leaked a path or omitted bounded code context: %s", stdin)
	}
	cwd, err := os.ReadFile(filepath.Join(markerDir, "cwd"))
	if err != nil || strings.Contains(string(cwd), root) {
		t.Fatalf("CLI cwd was project path: %q (%v)", cwd, err)
	}
	args, err := os.ReadFile(filepath.Join(markerDir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--ignore-user-config", "--ignore-rules", "--ephemeral", "--sandbox", "read-only", "features.shell_tool=false", "web_search=\"disabled\"", "mcp_servers={}", "history.persistence=\"none\"", "developer_instructions="} {
		if !strings.Contains(string(args), required) {
			t.Errorf("Codex args missing %q: %s", required, args)
		}
	}
	if strings.Contains(string(args), "model_instructions_file=") || strings.Contains(string(args), "instructions.md") {
		t.Fatalf("Codex args must not depend on a model instructions file: %s", args)
	}
}

func TestClaudeCheckUsesRestrictedNoToolsAndNoProjectInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a shell script")
	}
	binDir := t.TempDir()
	markerDir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' "$@" > "$MITNICK_ARGS"
cat > "$MITNICK_INPUT"
printf '%s' '{"type":"result","subtype":"success","is_error":false,"result":"{\"observations\":[]}"}'
`
	writeFakeCLI(t, binDir, Claude, script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MITNICK_ARGS", filepath.Join(markerDir, "args"))
	t.Setenv("MITNICK_INPUT", filepath.Join(markerDir, "input"))
	if err := Check(context.Background(), Options{Provider: Claude}); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(filepath.Join(markerDir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--restricted", "--safe-mode", "--no-session-persistence", "--tools", "--disallowedTools", "mcp__*", "--strict-mcp-config", "--max-turns", "1"} {
		if !strings.Contains(string(args), required) {
			t.Errorf("Claude args missing %q: %s", required, args)
		}
	}
	input, err := os.ReadFile(filepath.Join(markerDir, "input"))
	if err != nil || strings.Contains(string(input), "project source") {
		t.Fatalf("content-free test sent project data: %q (%v)", input, err)
	}
}

func TestConnectChecksExistingCLIAuthentication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a shell script")
	}
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$MITNICK_CALLS"
if [ "$1" = "--version" ]; then echo 2.1.268; exit 0; fi
if [ "$1" = "auth" ]; then echo authenticated; exit 0; fi
exit 1
`
	writeFakeCLI(t, binDir, Claude, script)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MITNICK_CALLS", marker)
	if err := Connect(context.Background(), Claude); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(calls), "--version") || !strings.Contains(string(calls), "auth status --text") {
		t.Fatalf("connect did not check CLI version and auth: %q (%v)", calls, err)
	}
}

func TestClaudeRestrictedMinimumVersion(t *testing.T) {
	for _, test := range []struct {
		version string
		want    bool
	}{{"2.1.247", false}, {"2.1.248", true}, {"2.2.0", true}, {"v3.0.0", true}, {"unknown", false}} {
		if got := claudeVersionSupported(test.version); got != test.want {
			t.Errorf("claudeVersionSupported(%q) = %t, want %t", test.version, got, test.want)
		}
	}
}

func TestBuildPromptRedactsSecretsOmitsPathsAndBoundsFindings(t *testing.T) {
	filePath := "/private/project/src/app.js"
	finding := findings.Finding{
		ID: "mitnick/web002", RuleID: "WEB002", Fingerprint: "fp", Domain: "code",
		Severity: "high", Confidence: "medium", State: "suspected",
		Location: findings.Location{File: filePath, Line: 1},
	}
	files := []scanner.File{{Path: filePath, Content: []byte("token=supersecretvalue123\nunsafe();\n")}}
	items := make([]findings.Finding, 22)
	for i := range items {
		items[i] = finding
		items[i].ID = fmt.Sprintf("mitnick/web002-%d", i)
		items[i].Fingerprint = fmt.Sprintf("fp-%d", i)
	}
	prompt := buildPrompt(items, files)
	if strings.Contains(prompt, "supersecretvalue123") || strings.Contains(prompt, filePath) {
		t.Fatal("prompt leaked a secret or source path")
	}
	if strings.Count(prompt, `"finding_id"`) != 20 {
		t.Fatalf("prompt included more than 20 findings: %d", strings.Count(prompt, `"finding_id"`))
	}
	if len(prompt) > maxAIRequestBytes {
		t.Fatalf("prompt size = %d; limit %d", len(prompt), maxAIRequestBytes)
	}
}

func TestObservationParserRejectsCorrectionContentAndUnknownFields(t *testing.T) {
	finding := findings.Finding{ID: "finding-1", Fingerprint: "fp-1", CWEIDs: []string{"CWE-89"}}
	valid := `{"observations":[{"finding_id":"finding-1","finding_fingerprint":"fp-1","analysis_type":"contextual_review","assessment":"inconclusive","summary":"A evidência é limitada.","evidence_refs":["finding:fp-1"],"cwe_ids":["CWE-89"],"confidence":"low","limitations":["Análise consultiva."],"references":[]}]}`
	if reviews, err := parseObservations(valid, []findings.Finding{finding}); err != nil || len(reviews) != 1 {
		t.Fatalf("valid response rejected: %#v, %v", reviews, err)
	}
	for _, response := range []string{
		strings.Replace(valid, "A evidência é limitada.", "```diff", 1),
		strings.Replace(valid, `"references":[]`, `"references":[],"patch":"x"`, 1),
		strings.Replace(valid, "finding:fp-1", "finding:invented", 1),
	} {
		if _, err := parseObservations(response, []findings.Finding{finding}); err == nil {
			t.Errorf("unsafe response accepted: %s", response)
		}
	}
}

func TestProviderArgumentsStayReadOnlyAndNoContentEntersArguments(t *testing.T) {
	workdir := filepath.Join(t.TempDir(), "private dir")
	args := codexReviewArgs(workdir)
	codexArgs := strings.Join(args, "\n")
	claudeArgs := strings.Join(claudeReviewArgs(), "\n")
	if len(args) < 3 || strings.Join(args[:3], " ") != "--ask-for-approval never exec" {
		t.Fatalf("Codex global approval flag must precede exec: %#v", args[:min(len(args), 3)])
	}
	for _, required := range []string{"--sandbox\nread-only", "features.shell_tool=false", "--ignore-user-config", "--ignore-rules", "--ephemeral", "developer_instructions=", workdir} {
		if !strings.Contains(codexArgs, required) {
			t.Errorf("Codex restrictions missing %q", required)
		}
	}
	if strings.Contains(codexArgs, "model_instructions_file=") {
		t.Fatal("Codex args must not depend on a model instructions file")
	}
	for _, required := range []string{"--restricted", "--tools\n", "--disallowedTools\nmcp__*", "--no-session-persistence", "--max-turns\n1"} {
		if !strings.Contains(claudeArgs, required) {
			t.Errorf("Claude restrictions missing %q", required)
		}
	}
	if strings.Contains(codexArgs, "mitnick/web002") || strings.Contains(claudeArgs, "mitnick/web002") || strings.Contains(codexArgs, "project source") || strings.Contains(claudeArgs, "project source") {
		t.Fatal("dynamic project content was placed in process arguments")
	}
}

func TestCodexExecutionFailureExplainsSandboxSetup(t *testing.T) {
	for _, test := range []struct {
		stderr string
		want   string
	}{
		{"error building bubblewrap command: app-server socket directory must be a user-owned directory with mode 0700", "diretório app-server-control"},
		{"bwrap: No permissions to create a new namespace", "bubblewrap"},
		{"error sending request for url: DNS lookup failed (Operation not permitted)", "não alcançou o provedor"},
		{"401 unauthorized: authentication failed", "recusou a autenticação"},
	} {
		err := codexExecutionError(&processRunError{cause: errors.New("exit status 1"), stderr: test.stderr})
		if !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), test.stderr) {
			t.Errorf("codexExecutionError() = %q; want safe hint containing %q", err, test.want)
		}
	}
}

func writeFakeCLI(t *testing.T, directory, name, script string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}
