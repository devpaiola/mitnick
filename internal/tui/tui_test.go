package tui

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mitnick-security/mitnick/internal/config"
	"github.com/mitnick-security/mitnick/internal/core"
	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/reporter"
)

func press(model *Model, name string) {
	var key tea.KeyMsg
	switch name {
	case "up":
		key.Type = tea.KeyUp
	case "down":
		key.Type = tea.KeyDown
	case "enter":
		key.Type = tea.KeyEnter
	case "ctrl+c":
		key.Type = tea.KeyCtrlC
	default:
		key.Type = tea.KeyRunes
		key.Runes = []rune(name)
	}
	_, _ = model.Update(key)
}

func TestCtrlCCancelsActiveTUIContext(t *testing.T) {
	model := NewModel(context.Background())
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if command == nil || model.ctx.Err() != context.Canceled || !model.interrupted {
		t.Fatal("Ctrl+C did not cancel active operations and mark an interrupted exit")
	}
	formModel := NewModel(context.Background())
	formModel.current = screenForm
	_, command = formModel.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if command == nil || formModel.ctx.Err() != context.Canceled {
		t.Fatal("Ctrl+C did not cancel operations from an active form")
	}
}

func TestKeyboardMenuAndScanPrivacyDefaults(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	model := NewModel(context.Background())
	_, _ = model.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	if !strings.Contains(model.View(), "Scan Project") {
		t.Fatal("main menu does not show scan action")
	}
	press(model, "down")
	press(model, "up")
	press(model, "enter")
	if model.current != screenScan {
		t.Fatalf("menu enter opened %q, want scan", model.current)
	}
	if model.scanAI || model.contentConsent {
		t.Fatal("AI or external consent was enabled by default")
	}
	press(model, "a")
	if !model.scanAI {
		t.Fatal("keyboard did not enable explicit AI opt-in")
	}
	press(model, "r")
	if model.contentConsent {
		t.Fatal("content consent was granted before a CLI was connected")
	}
	_, _ = model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if model.current != screenScan || !model.scanAI || model.contentConsent {
		t.Fatal("terminal resize lost security state")
	}
}

func TestScanConsentIsExplicitOneTimeAndConsumed(t *testing.T) {
	model := NewModel(context.Background())
	model.current = screenScan
	model.scanAI = true
	model.aiSet = true
	model.aiProfile = config.AIConfig{Provider: "codex"}
	press(model, "r")
	if !model.contentConsent {
		t.Fatal("scan context consent was not granted")
	}
	if got := model.takeContentConsent(); !got {
		t.Fatal("scan did not consume granted content consent")
	}
	if model.contentConsent || !model.inFlightContentConsent {
		t.Fatal("content consent was not consumed into the active scan")
	}
	if got := model.takeContentConsent(); got {
		t.Fatal("one-time consent was reused for a second scan")
	}
}

func TestTUIListsAndConnectsSelectedCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a shell script")
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	binDir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo 2.1.268; exit 0; fi
if [ "$1" = "auth" ]; then echo authenticated; exit 0; fi
exit 1
`
	if err := os.WriteFile(filepath.Join(binDir, "claude"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	model := NewModel(context.Background())
	model.current = screenAI
	view := model.View()
	if !strings.Contains(view, "Codex CLI") || !strings.Contains(view, "Claude Code") {
		t.Fatalf("AI screen does not list selectable clients: %s", view)
	}
	press(model, "down")
	if model.aiChoiceIndex != 1 {
		t.Fatalf("down selected provider index %d, want Claude", model.aiChoiceIndex)
	}
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if command == nil || !model.busy {
		t.Fatal("Enter did not start the selected CLI connection")
	}
	message := command().(aiConnectDoneMsg)
	_, _ = model.Update(message)
	if !model.aiSet || model.aiProfile.Provider != "claude" {
		t.Fatalf("selected CLI was not saved: %#v", model.aiProfile)
	}
	if !strings.Contains(model.status, "Use t para testar") {
		t.Fatalf("successful connect did not explain how to use the CLI: %s", model.status)
	}
}

func TestAIIntegrationNumberSelectsClientWithoutConnecting(t *testing.T) {
	model := NewModel(context.Background())
	model.current = screenAI
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	if command != nil || updated.(*Model).aiChoiceIndex != 1 || !strings.Contains(model.View(), "> Claude Code") {
		t.Fatalf("2 did not select Claude without starting a connection: index=%d command=%v view=%s", model.aiChoiceIndex, command != nil, model.View())
	}
}

func TestAIModelCheckReturnsToIntegrationScreen(t *testing.T) {
	model := NewModel(context.Background())
	model.current = screenAI
	model.busy = true
	_, _ = model.Update(aiCheckDoneMsg{})
	if model.current != screenAI || model.busy || !strings.Contains(model.View(), "Teste sem código concluído") {
		t.Fatalf("model test did not return its result to AI Integrations: screen=%q busy=%t view=%s", model.current, model.busy, model.View())
	}
}

func TestIntelUpdateRequiresExplicitKeypress(t *testing.T) {
	model := NewModel(context.Background())
	model.current = screenIntel
	if model.Init() != nil || model.busy {
		t.Fatal("opening TUI started an intelligence update")
	}
	if !strings.Contains(model.View(), "cwe.mitre.org") || !strings.Contains(model.View(), "cisa.gov") {
		t.Fatal("intel screen does not disclose network update destinations")
	}
	updated, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("u")})
	if command == nil || !updated.(*Model).busy {
		t.Fatal("u did not start the explicit intelligence update action")
	}
}

func TestIntelQueryUsesCuratedOfflineCWEData(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	message := intelQueryCommand(context.Background(), "cwe-89")().(intelQueryDoneMsg)
	if message.err != nil {
		t.Fatal(message.err)
	}
	if message.title != "Weakness Intelligence · CWE-89" || !strings.Contains(strings.Join(message.lines, "\n"), "A05:2025") {
		t.Fatalf("unexpected offline CWE query: %#v", message)
	}
}

func TestFindingsFilterCoversSeverityTechnologyOriginCWEAndCVE(t *testing.T) {
	item := findings.Finding{RuleID: "CVE-2025-1234", Title: "Vulnerable dependency", Domain: "dependency", Severity: "high", Origin: "osv", Location: findings.Location{File: "package-lock.json"}, CWEIDs: []string{"CWE-79"}, AdvisoryIDs: []string{"GHSA-abcd-1234"}}
	for _, query := range []string{"high", "dependency", "osv", "CWE-79", "CVE-2025-1234", "GHSA-abcd-1234"} {
		if !findingMatches(item, query) {
			t.Errorf("filter %q did not match finding", query)
		}
	}
	if findingMatches(item, "critical") {
		t.Fatal("filter matched a value absent from the finding")
	}
}

func TestExportRefusesProjectFilesAndDoesNotOverwrite(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("const safe = true;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := safeExportPath(root, filepath.Join(root, "report.json")); err == nil {
		t.Fatal("export path inside scanned project was accepted")
	}
	destination := filepath.Join(t.TempDir(), "report.json")
	report := reporter.JSONReport{Result: core.Result{SchemaVersion: "1.0", Target: root}}
	msg := exportCommand(context.Background(), report, root, "json", destination)().(exportDoneMsg)
	if msg.err != nil {
		t.Fatalf("export failed: %v", msg.err)
	}
	before, err := os.ReadFile(destination)
	if err != nil || !strings.Contains(string(before), `"schema_version": "1.0"`) {
		t.Fatalf("export did not create JSON report: %s (%v)", before, err)
	}
	msg = exportCommand(context.Background(), report, root, "json", destination)().(exportDoneMsg)
	if msg.err == nil || !strings.Contains(msg.err.Error(), "não sobrescreve") {
		t.Fatalf("existing report was not protected: %v", msg.err)
	}
	after, err := os.ReadFile(destination)
	if err != nil || string(after) != string(before) {
		t.Fatalf("existing report changed: %s (%v)", after, err)
	}
}

func TestExportResolvesSymlinkedDirectoryBeforeProjectBoundaryCheck(t *testing.T) {
	root := t.TempDir()
	parent := t.TempDir()
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := safeExportPath(root, filepath.Join(link, "report.json")); err == nil {
		t.Fatal("symlinked path inside project was accepted for export")
	}
	if _, err := safeExportPath(root, filepath.Join(parent, "report.json")); err != nil {
		t.Fatalf("path outside project rejected: %v", err)
	}
}
