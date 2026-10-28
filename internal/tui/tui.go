// Package tui provides the keyboard-only terminal UI. It calls the same Core,
// intelligence, AI and reporter services as the CLI and never invokes tools
// from the repository.
package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mitnick-security/mitnick/internal/ai"
	"github.com/mitnick-security/mitnick/internal/config"
	"github.com/mitnick-security/mitnick/internal/core"
	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/intelligence"
	"github.com/mitnick-security/mitnick/internal/reporter"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

var buildVersion = "0.1.0-dev"

type screen string

const (
	screenMenu        screen = "menu"
	screenScan        screen = "scan"
	screenFindings    screen = "findings"
	screenFinding     screen = "finding"
	screenAgents      screen = "agents"
	screenAI          screen = "ai"
	screenIntel       screen = "intel"
	screenReports     screen = "reports"
	screenPreview     screen = "preview"
	screenPrivacy     screen = "privacy"
	screenDiagnostics screen = "diagnostics"
	screenHelp        screen = "help"
	screenForm        screen = "form"
)

var menuItems = []string{
	"Scan Project",
	"Findings & Evidence",
	"AI Integrations",
	"Agent Security",
	"Vulnerability Intelligence",
	"Reports & Export",
	"Policies & Privacy",
	"System Diagnostics",
	"Help",
}

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#006B5B", Dark: "#5EEAD4"})
	selectedStyle = lipgloss.NewStyle().Bold(true)
	mutedStyle    = lipgloss.NewStyle().Faint(true)
)

// ErrRequiresTerminal signals that the interactive menu needs a terminal on
// both input and output. The no-argument CLI checks this and prints help in CI.
var ErrRequiresTerminal = errors.New("a TUI exige um terminal interativo; use `mitnick --help` em pipelines")

type formKind string

const (
	formTarget     formKind = "target"
	formFilter     formKind = "filter"
	formExport     formKind = "export"
	formIntelQuery formKind = "intel_query"
)

type Model struct {
	ctx    context.Context
	cancel context.CancelFunc

	current                screen
	previous               screen
	cursor                 int
	width                  int
	height                 int
	target                 string
	filter                 string
	status                 string
	lastError              string
	busy                   bool
	agentOnly              bool
	scanAI                 bool
	contentConsent         bool
	inFlightContentConsent bool
	aiChoiceIndex          int
	interrupted            bool

	result    core.Result
	hasResult bool
	reviews   []reporter.AIReview
	aiMeta    *reporter.AIMetadata

	findingRows []findings.Finding
	detailIndex int
	rowIndex    int
	lineOffset  int

	aiProfile config.AIConfig
	aiSet     bool
	intelPath string
	intelRows []intelligence.SourceStatus

	formKind   formKind
	formIndex  int
	formValues []string
	formLabels []string
	input      textinput.Model
	inputCmd   tea.Cmd
	formErr    string

	previewTitle string
	previewLines []string
}

type scanDoneMsg struct {
	report reporter.JSONReport
	err    error
}

type intelDoneMsg struct {
	path    string
	status  []intelligence.SourceStatus
	err     error
	updated bool
}

type intelQueryDoneMsg struct {
	title string
	lines []string
	err   error
}

type exportDoneMsg struct{ err error }
type aiCheckDoneMsg struct{ err error }
type aiConnectDoneMsg struct {
	provider string
	path     string
	err      error
}

func NewModel(ctx context.Context) *Model {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Model{ctx: ctx, cancel: cancel, current: screenMenu, target: ".", input: newInput(72)}
}

func Run(ctx context.Context, in io.Reader, out io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	model := NewModel(ctx)
	defer model.cancel()
	program := tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen())
	_, err := program.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if model.interrupted {
		return context.Canceled
	}
	return err
}

func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.width > 0 {
			m.input.Width = m.width - 8
		}
		return m, nil
	case scanDoneMsg:
		m.busy = false
		m.inFlightContentConsent = false
		if msg.err != nil {
			m.lastError = msg.err.Error()
			m.current = screenScan
			return m, nil
		}
		m.result = msg.report.Result
		m.reviews = msg.report.AIReviews
		m.aiMeta = msg.report.AI
		m.hasResult = true
		m.rebuildFindingRows()
	case aiConnectDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.lastError = msg.err.Error()
			return m, nil
		}
		m.aiProfile = config.AIConfig{Provider: msg.provider}
		m.aiSet = true
		m.aiChoiceIndex = aiProviderIndex(msg.provider)
		m.status = msg.provider + " autenticado e selecionado. Use t para testar ou volte ao scan para usá-lo."
	case aiCheckDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.lastError = msg.err.Error()
		} else {
			m.status = "Teste sem código concluído; o CLI pode ter consumido créditos."
		}
		m.current = screenAI
		return m, nil
	case intelDoneMsg:
		m.busy = false
		m.intelPath, m.intelRows = msg.path, msg.status
		if msg.err != nil {
			m.lastError = msg.err.Error()
		} else if msg.updated {
			m.lastError = ""
			m.status = "MITRE CWE e CISA KEV atualizados; OSV consultou as dependências resolvidas do alvo."
		}
		m.current = screenIntel
		return m, nil
	case intelQueryDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.lastError = msg.err.Error()
			m.current = screenIntel
		} else {
			m.lastError = ""
			m.previewTitle, m.previewLines = msg.title, msg.lines
			m.lineOffset = 0
			m.current = screenPreview
		}
		return m, nil
	case exportDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.lastError = msg.err.Error()
		} else {
			m.status = "Relatório exportado com arquivo novo e permissão privada."
		}
		m.current = screenReports
		return m, nil
	case tea.KeyMsg:
		return m.updateKey(msg)
	}
	return m, nil
}

func (m *Model) updateKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	name := key.String()
	if name == "ctrl+c" {
		m.interrupted = true
		m.cancel()
		return m, tea.Quit
	}
	if name == "q" {
		m.cancel()
		return m, tea.Quit
	}
	if m.current == screenForm {
		return m.updateFormKey(key)
	}
	if m.busy {
		return m, nil
	}
	if name == "esc" || name == "backspace" {
		if m.current == screenScan {
			m.contentConsent = false
		}
		m.current = screenMenu
		m.status = ""
		m.lastError = ""
		m.lineOffset = 0
		return m, nil
	}
	switch m.current {
	case screenMenu:
		switch name {
		case "up", "k":
			m.cursor = (m.cursor + len(menuItems) - 1) % len(menuItems)
		case "down", "j":
			m.cursor = (m.cursor + 1) % len(menuItems)
		case "e":
			if m.cursor == 0 {
				m.beginForm(formTarget, screenScan, []string{"Project path"}, []string{m.target})
			}
		case "enter":
			return m.selectMenuItem()
		}
	case screenScan:
		switch name {
		case "e":
			m.beginForm(formTarget, screenScan, []string{"Project path"}, []string{m.target})
		case "a":
			m.scanAI = !m.scanAI
			if !m.scanAI {
				m.contentConsent = false
			}
			m.status = "AI opt-in " + onOff(m.scanAI)
		case "r":
			if !m.scanAI || !m.aiSet {
				m.lastError = "conecte Codex ou Claude e habilite a revisão por IA antes de consentir"
			} else {
				m.contentConsent = !m.contentConsent
				m.status = "Consentimento para enviar contexto " + onOff(m.contentConsent)
			}
		case "enter":
			if m.scanAI && !m.aiSet {
				m.lastError = "nenhuma IA conectada; abra AI Integrations e conecte Codex ou Claude Code"
				break
			}
			if m.scanAI && !m.contentConsent {
				m.lastError = "pressione r para autorizar o envio dos findings e do contexto sanitizado ao CLI selecionado"
				break
			}
			m.lastError, m.status = "", ""
			m.agentOnly = false
			m.busy = true
			return m, scanCommand(m.ctx, m.target, m.scanAI, m.takeContentConsent())
		}
	case screenFindings, screenAgents:
		rows := m.visibleFindings()
		switch name {
		case "up", "k":
			if m.rowIndex > 0 {
				m.rowIndex--
			}
		case "down", "j":
			if m.rowIndex+1 < len(rows) {
				m.rowIndex++
			}
		case "/":
			m.beginForm(formFilter, m.current, []string{"Filter (severity, file, origin, CWE, CVE or text)"}, []string{m.filter})
		case "enter":
			if len(rows) > 0 {
				m.detailIndex = m.findingIndex(rows[m.rowIndex].Fingerprint)
				m.lineOffset = 0
				m.current = screenFinding
			}
		case "c":
			m.filter = ""
			m.rowIndex = 0
		}
	case screenFinding:
		switch name {
		case "up", "k":
			if m.lineOffset > 0 {
				m.lineOffset--
			}
		case "down", "j":
			m.lineOffset++
		}
	case screenAI:
		if name == "1" || name == "2" {
			m.aiChoiceIndex = int(name[0] - '1')
			m.lastError = ""
			m.status = "Selecionado: " + []string{ai.Codex, ai.Claude}[m.aiChoiceIndex] + ". Pressione Enter para verificar o login."
			return m, nil
		}
		if name == "up" || name == "k" {
			m.aiChoiceIndex = (m.aiChoiceIndex + 1) % 2
			m.lastError = ""
			return m, nil
		}
		if name == "down" || name == "j" {
			m.aiChoiceIndex = (m.aiChoiceIndex + 1) % 2
			m.lastError = ""
			return m, nil
		}
		switch name {
		case "enter", "c":
			provider := []string{ai.Codex, ai.Claude}[m.aiChoiceIndex]
			m.busy = true
			m.lastError, m.status = "", ""
			m.status = "Verificando autenticação do " + provider + "…"
			return m, aiConnectCommand(m.ctx, provider)
		case "t":
			provider := []string{ai.Codex, ai.Claude}[m.aiChoiceIndex]
			if !m.aiSet || m.aiProfile.Provider != provider {
				m.lastError = "selecione e conecte este CLI antes de testar"
				break
			}
			m.busy = true
			m.lastError, m.status = "", ""
			m.status = "Enviando teste sem código; o CLI pode consumir créditos…"
			return m, aiCheckCommand(m.ctx, provider)
		case "d":
			m.lastError = ""
			m.status = "Lista atualizada; o Mitnick só consultou o PATH."
		}
	case screenIntel:
		switch name {
		case "/":
			m.beginForm(formIntelQuery, screenIntel, []string{"CWE-ID, CVE-ID or GHSA-ID"}, []string{""})
		case "u":
			m.busy = true
			m.lastError = ""
			m.status = "Sincronizando MITRE CWE, CISA KEV e OSV pela rede…"
			return m, intelUpdateCommand(m.ctx, m.target)
		}
	case screenReports:
		switch name {
		case "j":
			if m.hasResult {
				m.beginForm(formExport, screenReports, []string{"New JSON report path outside the scanned project"}, []string{""})
				m.previewTitle = "json"
			}
		case "s":
			if m.hasResult {
				m.beginForm(formExport, screenReports, []string{"New SARIF report path outside the scanned project"}, []string{""})
				m.previewTitle = "sarif"
			}
		case "v":
			m.showPreview("terminal")
		}
	case screenPreview:
		switch name {
		case "up", "k":
			if m.lineOffset > 0 {
				m.lineOffset--
			}
		case "down", "j":
			m.lineOffset++
		case "left", "h":
			m.showPreview("terminal")
		}
	}
	return m, nil
}

func (m *Model) selectMenuItem() (tea.Model, tea.Cmd) {
	m.status, m.lastError = "", ""
	switch m.cursor {
	case 0:
		m.loadAIProfile()
		m.current = screenScan
	case 1:
		if m.hasResult {
			m.current = screenFindings
		} else {
			m.status = "Execute Scan Project antes de abrir findings."
		}
	case 2:
		m.loadAIProfile()
		m.current = screenAI
	case 3:
		if m.hasResult {
			m.current = screenAgents
		} else {
			m.agentOnly = true
			m.busy = true
			return m, scanCommand(m.ctx, m.target, false, false)
		}
	case 4:
		m.busy = true
		return m, intelCommand(m.ctx)
	case 5:
		m.current = screenReports
	case 6:
		m.current = screenPrivacy
	case 7:
		m.current = screenDiagnostics
	case 8:
		m.current = screenHelp
	}
	return m, nil
}

func (m *Model) beginForm(kind formKind, previous screen, labels, values []string) {
	m.previous = previous
	m.current = screenForm
	m.formKind = kind
	m.formLabels = append([]string(nil), labels...)
	m.formValues = append([]string(nil), values...)
	m.formIndex = 0
	m.formErr = ""
	m.prepareInput()
}

func (m *Model) prepareInput() {
	m.input = newInput(max(20, m.width-8))
	m.input.SetValue(m.formValues[m.formIndex])
	m.input.Focus()
	m.inputCmd = m.input.Cursor.BlinkCmd()
}

func newInput(width int) textinput.Model {
	input := textinput.New()
	input.CharLimit = 4096
	input.Width = width
	input.Prompt = "> "
	// The default paste binding reads the system clipboard via external helpers.
	// Bracketed terminal paste still works, but Ctrl+V never starts a process.
	input.KeyMap.Paste = key.Binding{}
	return input
}

func (m *Model) updateFormKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "esc" {
		m.current = m.previous
		m.formErr = ""
		return m, nil
	}
	if key.String() != "enter" {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(key)
		return m, cmd
	}
	value := strings.TrimSpace(m.input.Value())
	m.formValues[m.formIndex] = value
	if m.formIndex+1 < len(m.formValues) {
		m.formIndex++
		m.formErr = ""
		m.prepareInput()
		return m, m.inputCmd
	}
	switch m.formKind {
	case formTarget:
		if value == "" {
			m.formErr = "caminho do projeto não pode ficar vazio"
			return m, nil
		}
		m.target = value
		m.current = screenScan
	case formFilter:
		m.filter = value
		m.rowIndex = 0
		m.rebuildFindingRows()
		m.current = m.previous
	case formIntelQuery:
		if value == "" {
			m.formErr = "informe um identificador CWE, CVE ou GHSA"
			return m, nil
		}
		m.busy = true
		m.lastError, m.status = "", ""
		m.current = screenIntel
		return m, intelQueryCommand(m.ctx, value)
	case formExport:
		if value == "" {
			m.formErr = "informe o caminho de destino"
			return m, nil
		}
		format := m.previewTitle
		m.busy = true
		m.current = screenReports
		return m, exportCommand(m.ctx, m.makeReport(), m.result.Target, format, value)
	}
	m.formKind = ""
	m.formErr = ""
	return m, nil
}

func (m *Model) loadAIProfile() {
	profile, _, found, err := config.LoadAIProfile()
	if err != nil {
		m.lastError = err.Error()
		m.aiProfile = config.AIConfig{}
		m.aiSet = false
		return
	}
	m.aiProfile = profile
	m.aiSet = found
	m.aiChoiceIndex = aiProviderIndex(m.aiProfile.Provider)
}

func aiProviderIndex(provider string) int {
	if provider == ai.Claude {
		return 1
	}
	return 0
}

func (m *Model) takeContentConsent() bool {
	consented := m.contentConsent
	m.contentConsent = false
	m.inFlightContentConsent = consented
	return consented
}

func (m *Model) rebuildFindingRows() {
	m.findingRows = make([]findings.Finding, 0, len(m.result.Findings))
	for _, item := range m.result.Findings {
		if m.filter != "" && !findingMatches(item, m.filter) {
			continue
		}
		m.findingRows = append(m.findingRows, item)
	}
	if m.rowIndex >= len(m.visibleFindings()) {
		m.rowIndex = max(0, len(m.visibleFindings())-1)
	}
}

func findingMatches(item findings.Finding, filter string) bool {
	parts := []string{item.ID, item.RuleID, item.Title, item.Description, item.Domain, item.Severity, item.Confidence, item.State, item.Location.File, item.Evidence, item.Origin, item.Priority}
	parts = append(parts, item.CWEIDs...)
	parts = append(parts, item.OWASPIDs...)
	parts = append(parts, item.AdvisoryIDs...)
	parts = append(parts, item.References...)
	if item.Detector != nil {
		parts = append(parts, item.Detector.Name, item.Detector.Version)
	}
	needle := strings.ToLower(strings.TrimSpace(filter))
	for _, part := range parts {
		if strings.Contains(strings.ToLower(part), needle) {
			return true
		}
	}
	return false
}

func (m *Model) visibleFindings() []findings.Finding {
	if m.current != screenAgents {
		return m.findingRows
	}
	rows := make([]findings.Finding, 0)
	for _, item := range m.findingRows {
		if item.Domain == "agent" {
			rows = append(rows, item)
		}
	}
	return rows
}

func (m *Model) findingIndex(fingerprint string) int {
	for index, item := range m.result.Findings {
		if item.Fingerprint == fingerprint {
			return index
		}
	}
	return 0
}

func (m *Model) makeReport() reporter.JSONReport {
	return reporter.JSONReport{Result: m.result, AIReviews: m.reviews, AI: m.aiMeta}
}

func (m *Model) showPreview(format string) {
	var output bytes.Buffer
	var err error
	switch format {
	case "json":
		m.previewTitle = "JSON report"
		err = reporter.WriteJSON(&output, m.makeReport())
	case "sarif":
		m.previewTitle = "SARIF"
		err = reporter.WriteSARIF(&output, m.result)
	default:
		m.previewTitle = "Terminal report"
		err = reporter.WriteTerminal(&output, m.result, m.reviews)
	}
	if err != nil {
		m.lastError = err.Error()
		return
	}
	m.previewLines = strings.Split(strings.TrimRight(output.String(), "\n"), "\n")
	m.lineOffset = 0
	m.current = screenPreview
}

func (m *Model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("MITNICK · Security Platform"))
	b.WriteString("\n")
	switch m.current {
	case screenMenu:
		m.viewMenu(&b)
	case screenScan:
		m.viewScan(&b)
	case screenFindings, screenAgents:
		m.viewFindings(&b)
	case screenFinding:
		m.viewFinding(&b)
	case screenAI:
		m.viewAI(&b)
	case screenIntel:
		m.viewIntel(&b)
	case screenReports:
		m.viewReports(&b)
	case screenPreview:
		m.viewPreview(&b)
	case screenPrivacy:
		m.viewPrivacy(&b)
	case screenDiagnostics:
		m.viewDiagnostics(&b)
	case screenHelp:
		m.viewHelp(&b)
	case screenForm:
		m.viewForm(&b)
	}
	if m.status != "" {
		fmt.Fprintf(&b, "\n%s\n", mutedStyle.Render(safePreviewLine(m.status)))
	}
	if m.lastError != "" {
		fmt.Fprintf(&b, "\nAviso: %s\n", safePreviewLine(m.lastError))
	}
	b.WriteString("\n")
	switch m.current {
	case screenMenu:
		b.WriteString("↑/k ↓/j mover · Enter abrir · e editar caminho · q sair")
	case screenScan:
		b.WriteString("Enter iniciar scan · e caminho · a IA opt-in · r consentir envio à conta do CLI · Esc menu · q sair")
	case screenFindings, screenAgents:
		b.WriteString("↑/k ↓/j navegar · Enter detalhe · / filtrar · c limpar filtro · Esc menu")
	case screenFinding, screenPreview:
		b.WriteString("↑/k ↓/j rolar · Esc voltar")
	case screenAI:
		b.WriteString("↑/k ↓/j ou 1/2 selecionar · Enter conectar · t testar sem código · d atualizar lista · Esc voltar")
	case screenIntel:
		b.WriteString("/ consultar CWE/CVE/GHSA offline · u atualizar CWE, KEV e OSV (cwe.mitre.org, cisa.gov, osv.dev) · Esc menu")
	case screenReports:
		b.WriteString("v visualizar · j exportar JSON · s exportar SARIF · Esc menu")
	case screenForm:
		b.WriteString("Enter confirmar · Esc cancelar")
	default:
		b.WriteString("Esc voltar · q sair")
	}
	return b.String()
}

func (m *Model) viewMenu(b *strings.Builder) {
	b.WriteString("\nAudite projetos sem alterar seus arquivos.\n")
	for index, item := range menuItems {
		prefix := "  "
		label := item
		if index == m.cursor {
			prefix = "> "
			label = selectedStyle.Render(label)
		}
		fmt.Fprintf(b, "%s%s\n", prefix, label)
	}
	if m.hasResult {
		fmt.Fprintf(b, "\nÚltimo scan: %d arquivos · %d findings · alvo %s\n", m.result.FilesScanned, len(m.result.Findings), safePreviewLine(m.target))
	} else {
		fmt.Fprintf(b, "\nAlvo: %s\n", safePreviewLine(m.target))
	}
}

func (m *Model) viewScan(b *strings.Builder) {
	fmt.Fprintf(b, "\nScan Project\nAlvo: %s (e para editar)\n", safePreviewLine(m.target))
	fmt.Fprintf(b, "Regras determinísticas: habilitadas\nRevisão por IA: %s (a alterna; desabilitada por padrão)\n", onOff(m.scanAI))
	if m.scanAI {
		if m.aiSet {
			fmt.Fprintf(b, "CLI selecionado: %s · conta, modelo e roteamento são definidos pelo cliente.\n", safePreviewLine(m.aiProfile.Provider))
			b.WriteString("A revisão envia findings e contexto sanitizado ao serviço configurado nesse CLI; pode consumir créditos.\n")
		} else {
			b.WriteString("Nenhum CLI conectado; abra AI Integrations para conectar Codex ou Claude Code.\n")
		}
	}
	if m.aiSet && m.scanAI {
		if m.busy && m.inFlightContentConsent {
			b.WriteString("Consentimento para enviar contexto: aplicado a este scan\n")
		} else {
			fmt.Fprintf(b, "Consentimento para enviar contexto: %s (r alterna; necessário para iniciar)\n", onOff(m.contentConsent))
		}
	} else {
		b.WriteString("Nenhum contexto de projeto será enviado sem ativar IA e autorizar com r.\n")
	}
	if m.busy {
		b.WriteString("\nScan em andamento… Ctrl+C cancela.\n")
	}
	if m.hasResult {
		fmt.Fprintf(b, "\nÚltimo resultado: %d arquivos · %d findings · %d ignorados\n", m.result.FilesScanned, len(m.result.Findings), m.result.FilesSkipped)
		if len(m.result.EngineErrors) > 0 {
			fmt.Fprintf(b, "Cobertura incompleta: %d falha(s) operacional(is); consulte Findings e Reports.\n", len(m.result.EngineErrors))
		}
	}
}

func (m *Model) viewFindings(b *strings.Builder) {
	rows := m.visibleFindings()
	name := "Findings & Evidence"
	if m.current == screenAgents {
		name = "Agent Security"
	}
	fmt.Fprintf(b, "\n%s · %d item(ns)", name, len(rows))
	if m.filter != "" {
		fmt.Fprintf(b, " · filtro %q", safePreviewLine(m.filter))
	}
	b.WriteString("\n")
	if len(m.result.EngineErrors) > 0 {
		fmt.Fprintf(b, "Cobertura INCOMPLETA · %d falha(s) operacional(is)\n", len(m.result.EngineErrors))
		for _, failure := range m.result.EngineErrors {
			fmt.Fprintf(b, "  Falha: %s\n", safePreviewLine(failure))
		}
	}
	for _, warning := range m.result.Warnings {
		fmt.Fprintf(b, "  Aviso: %s\n", safePreviewLine(warning))
	}
	if len(rows) == 0 {
		b.WriteString("Nenhum finding corresponde ao filtro ou ao domínio selecionado.\n")
		return
	}
	start := max(0, m.rowIndex-6)
	end := min(len(rows), start+max(1, m.height-9))
	for index := start; index < end; index++ {
		item := rows[index]
		prefix := "  "
		line := fmt.Sprintf("[%-8s] %-18s %-36s %s:%d", safePreviewLine(strings.ToUpper(item.Severity)), safePreviewLine(item.RuleID), truncate(item.Title, 36), truncate(item.Location.File, 32), item.Location.Line)
		if index == m.rowIndex {
			prefix = "> "
			line = selectedStyle.Render(line)
		}
		fmt.Fprintf(b, "%s%s\n", prefix, line)
	}
	fmt.Fprintf(b, "\nMostrando %d–%d de %d · `/` filtra por severidade, tecnologia, origem, CWE/CVE ou texto.\n", start+1, end, len(rows))
}

func (m *Model) viewFinding(b *strings.Builder) {
	if m.detailIndex < 0 || m.detailIndex >= len(m.result.Findings) {
		b.WriteString("\nFinding indisponível.\n")
		return
	}
	item := m.result.Findings[m.detailIndex]
	lines := []string{
		"Finding & Evidence",
		fmt.Sprintf("ID: %s · Severity: %s", item.ID, strings.ToUpper(item.Severity)),
		fmt.Sprintf("Title: %s", item.Title),
		fmt.Sprintf("File: %s:%d", item.Location.File, item.Location.Line),
		fmt.Sprintf("Source: %s · Confidence: %s · State: %s", item.Origin, item.Confidence, item.State),
		"",
		item.Description,
		"Evidence: " + item.Evidence,
		"Recommendation: " + item.Recommendation,
	}
	if len(item.CWEIDs) > 0 {
		lines = append(lines, "CWE: "+strings.Join(item.CWEIDs, ", "))
	}
	if len(item.OWASPIDs) > 0 {
		lines = append(lines, "OWASP: "+strings.Join(item.OWASPIDs, ", "))
	}
	if len(item.AdvisoryIDs) > 0 {
		lines = append(lines, "Advisories: "+strings.Join(item.AdvisoryIDs, ", "))
	}
	for _, reference := range item.References {
		lines = append(lines, "Reference: "+reference)
	}
	for _, review := range m.reviews {
		if review.FindingFingerprint != item.Fingerprint {
			continue
		}
		lines = append(lines, "", "AI contextual review (consultive, unverified): "+review.Assessment+" · confidence "+review.Confidence, review.Summary)
		for _, limitation := range review.Limitations {
			lines = append(lines, "Limitation: "+limitation)
		}
	}
	for _, coverage := range m.result.Coverage {
		lines = append(lines, fmt.Sprintf("Coverage %s: %s", coverage.Component, coverage.Status))
	}
	for _, failure := range m.result.EngineErrors {
		lines = append(lines, "Operational failure: "+failure)
	}
	for _, warning := range m.result.Warnings {
		lines = append(lines, "Warning: "+warning)
	}
	writeScroll(b, lines, m.lineOffset, max(1, m.height-5))
}

func (m *Model) viewAI(b *strings.Builder) {
	b.WriteString("\nIntegrações de IA · conecte sua sessão do Codex CLI ou Claude Code\n")
	b.WriteString("↑/↓ ou 1/2 seleciona o cliente. Enter verifica o login existente e salva a seleção; não abre um chat nem inicia um scan.\n")
	installed := make(map[string]string)
	for _, client := range ai.Detect() {
		installed[client.Provider] = client.Binary
	}
	for index, provider := range []string{ai.Codex, ai.Claude} {
		label := "Claude Code"
		if provider == ai.Codex {
			label = "Codex CLI"
		}
		prefix := "  "
		if index == m.aiChoiceIndex {
			prefix = "> "
		}
		state := "não encontrado no PATH"
		if path, ok := installed[provider]; ok {
			state = "encontrado em " + safePreviewLine(path)
		}
		if m.aiProfile.Provider == provider {
			state += " · selecionado"
		}
		fmt.Fprintf(b, "%s%-12s %s\n", prefix, label, state)
	}
	if m.aiSet {
		fmt.Fprintf(b, "\nCLI conectado: %s\n", safePreviewLine(m.aiProfile.Provider))
	} else {
		b.WriteString("\nNenhum CLI selecionado.\n")
	}
	b.WriteString("O modelo e o destino seguem a conta/configuração do CLI. O teste t envia apenas um pedido sem código e pode consumir créditos.\n")
	b.WriteString("Para usar o CLI: t faz um teste sem código; ou Esc → Scan Project e pressione a, r e Enter.\n")
}

func (m *Model) viewIntel(b *strings.Builder) {
	fmt.Fprintf(b, "\nVulnerability Intelligence · local e offline\nCatálogo: %s\n", safePreviewLine(m.intelPath))
	if len(m.intelRows) == 0 {
		b.WriteString("Nenhuma fonte sincronizada. Use u para atualizar CWE, KEV e OSV; fontes por ID ficam na CLI.\n")
		return
	}
	for _, row := range m.intelRows {
		last := "never"
		if !row.LastSync.IsZero() {
			last = fmt.Sprintf("%s ago (%s)", time.Since(row.LastSync).Round(time.Second), row.LastSync.Format(time.RFC3339))
		}
		fmt.Fprintf(b, "%-28s %-12s records=%-5d last=%s\n", safePreviewLine(row.Name), safePreviewLine(row.State), row.RecordCount, safePreviewLine(last))
		if row.Error != "" {
			fmt.Fprintf(b, "  erro: %s\n", safePreviewLine(row.Error))
		}
	}
}

func (m *Model) viewReports(b *strings.Builder) {
	b.WriteString("\nReports & Export\n")
	if !m.hasResult {
		b.WriteString("Execute um scan para visualizar ou exportar relatórios JSON e SARIF.\n")
		return
	}
	fmt.Fprintf(b, "Último scan: %d findings · %d warnings · %d falhas operacionais\n", len(m.result.Findings), len(m.result.Warnings), len(m.result.EngineErrors))
	for _, failure := range m.result.EngineErrors {
		fmt.Fprintf(b, "Falha operacional: %s\n", safePreviewLine(failure))
	}
	b.WriteString("A exportação pede um caminho fora do projeto e cria somente um arquivo novo com modo privado.\n")
	b.WriteString("v visualiza relatório legível · j JSON · s SARIF\n")
}

func (m *Model) viewPreview(b *strings.Builder) {
	fmt.Fprintf(b, "\n%s\n", safePreviewLine(m.previewTitle))
	writeScroll(b, m.previewLines, m.lineOffset, max(1, m.height-5))
}

func (m *Model) viewPrivacy(b *strings.Builder) {
	b.WriteString(`
Policies & Privacy
- Scans determinísticos não fazem chamadas a IA.
- A revisão por Codex/Claude exige opt-in e consentimento por scan; o uso pode consumir créditos da conta do CLI.
- O modelo e o roteamento são definidos pelo Codex/Claude e por configurações da conta/organização; o Mitnick não consegue verificá-los.
- Contexto é limitado, secrets conhecidos são redigidos e arquivos de agentes não são enviados.
- Respostas são dados estritos e não podem criar findings, comandos, ferramentas ou patches.
- Mitnick não altera arquivos analisados nem lê credenciais privadas de outros agentes.
- A autenticação fica no CLI do cliente; o Mitnick salva somente qual CLI foi selecionado.
- Histórico e telemetria externa ficam desativados por padrão.
`)
}

func (m *Model) viewDiagnostics(b *strings.Builder) {
	fmt.Fprintf(b, "\nSystem Diagnostics\nMitnick build: %s\nPlatform: %s/%s\nGo: %s\nScan target: %s\n", buildVersion, runtime.GOOS, runtime.GOARCH, runtime.Version(), safePreviewLine(m.target))
	if cfg, path, err := config.Load(""); err != nil {
		fmt.Fprintf(b, "Configuração: inválida (%s)\n", safePreviewLine(err.Error()))
	} else {
		if path == "" {
			b.WriteString("Configuração: defaults\n")
		} else {
			fmt.Fprintf(b, "Configuração: %s (válida)\n", safePreviewLine(path))
		}
		fmt.Fprintf(b, "Workers: %d · timeout: %ds · threshold: %s\n", cfg.Workers, cfg.TimeoutSeconds, cfg.FailOn)
	}
	for _, binary := range []string{"gitleaks", "osv-scanner"} {
		if path, err := exec.LookPath(binary); err == nil {
			fmt.Fprintf(b, "%s disponível no PATH (%s); nenhum binário foi executado.\n", binary, safePreviewLine(path))
		} else {
			fmt.Fprintf(b, "%s não encontrado no PATH.\n", binary)
		}
	}
	b.WriteString("Rede: nenhum teste de conectividade foi iniciado por este diagnóstico.\n")
}

func (m *Model) viewHelp(b *strings.Builder) {
	b.WriteString(`
Help
Navigate with ↑/↓ or j/k and press Enter. Escape returns to the main menu.
Scan is deterministic and local by default. Press a on Scan Project to opt into AI review.
Open AI Integrations, select Codex CLI or Claude Code with ↑/↓, then press Enter to connect.
On Scan Project, press r to authorize sending sanitized findings/context for that scan.
The selected CLI controls the account, model, destination, and any usage charges.
The AI analyst is consultive: it returns grounded observations only.
No code, commands, diffs, patches or write actions are produced or applied.
`)
}

func (m *Model) viewForm(b *strings.Builder) {
	label := m.formLabels[m.formIndex]
	fmt.Fprintf(b, "\n%s · %d/%d\n%s\n%s", strings.ToUpper(string(m.formKind)), m.formIndex+1, len(m.formLabels), label, m.input.View())
	if m.formErr != "" {
		fmt.Fprintf(b, "\nErro: %s\n", safePreviewLine(m.formErr))
	}
}

func (m *Model) makeReportData() reporter.JSONReport { return m.makeReport() }

func writeScroll(b *strings.Builder, lines []string, offset, height int) {
	if offset >= len(lines) {
		offset = max(0, len(lines)-height)
	}
	end := min(len(lines), offset+height)
	for _, line := range lines[offset:end] {
		b.WriteString(safePreviewLine(line))
		b.WriteByte('\n')
	}
	if len(lines) > height {
		fmt.Fprintf(b, "[%d–%d de %d linhas]\n", offset+1, end, len(lines))
	}
}

func onOff(value bool) string {
	if value {
		return "ATIVO"
	}
	return "desativada"
}

func truncate(value string, maxRunes int) string {
	runes := []rune(safePreviewLine(value))
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes-1]) + "…"
}

func scanCommand(ctx context.Context, target string, aiEnabled, contentConsent bool) tea.Cmd {
	return func() tea.Msg {
		cfg, _, err := config.Load("")
		if err != nil {
			return scanDoneMsg{err: err}
		}
		selectedAI := ""
		if aiEnabled {
			profile, _, found, profileErr := config.LoadAIProfile()
			if profileErr != nil {
				return scanDoneMsg{err: profileErr}
			}
			if found {
				selectedAI = profile.Provider
			}
			if err := config.Validate(cfg); err != nil {
				return scanDoneMsg{err: err}
			}
		}
		timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
		result, err := core.Scan(ctx, target, core.Options{Workers: cfg.Workers, Timeout: timeout, Exclude: cfg.Exclude, ExcludeDirs: cfg.ExcludeDirs})
		if err != nil {
			return scanDoneMsg{err: err}
		}
		var reviews []reporter.AIReview
		var metadata *reporter.AIMetadata
		if aiEnabled {
			metadata = &reporter.AIMetadata{Enabled: true, Provider: selectedAI, PromptVersion: ai.PromptVersion, Consent: contentConsent}
			if selectedAI == "" {
				result.EngineErrors = append(result.EngineErrors, "AI review: conecte Codex ou Claude Code em AI Integrations")
			} else if len(result.Findings) > 0 && len(result.EngineErrors) == 0 {
				reviews, err = ai.Review(ctx, ai.Options{Provider: selectedAI, ContentConsent: contentConsent}, result.Findings, result.SourceFiles)
				if err != nil {
					result.EngineErrors = append(result.EngineErrors, "AI review: "+err.Error())
				}
			} else if len(result.Findings) > 0 {
				result.Warnings = append(result.Warnings, "revisão BYOAI ignorada porque o scan determinístico ficou incompleto")
			}
		}
		result.FinishedAt = time.Now().UTC()
		return scanDoneMsg{report: reporter.JSONReport{Result: result, AIReviews: reviews, AI: metadata}}
	}
}

func aiConnectCommand(ctx context.Context, provider string) tea.Cmd {
	return func() tea.Msg {
		if err := ai.Connect(ctx, provider); err != nil {
			return aiConnectDoneMsg{provider: provider, err: err}
		}
		path, err := config.WriteAIProfile(config.AIConfig{Provider: provider})
		return aiConnectDoneMsg{provider: provider, path: path, err: err}
	}
}

func aiCheckCommand(ctx context.Context, provider string) tea.Cmd {
	return func() tea.Msg {
		err := ai.Check(ctx, ai.Options{Provider: provider})
		return aiCheckDoneMsg{err: err}
	}
}

func intelCommand(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		store, err := intelligence.OpenDefault()
		if err != nil {
			return intelDoneMsg{err: err}
		}
		defer store.Close()
		if err := intelligence.SeedCurated(ctx, store); err != nil {
			return intelDoneMsg{path: store.Path(), err: err}
		}
		rows, err := store.Sources(ctx)
		return intelDoneMsg{path: store.Path(), status: rows, err: err}
	}
}

func intelQueryCommand(ctx context.Context, identifier string) tea.Cmd {
	return func() tea.Msg {
		identifier = strings.ToUpper(strings.TrimSpace(identifier))
		if len(identifier) > 64 || (!strings.HasPrefix(identifier, "CWE-") && !strings.HasPrefix(identifier, "CVE-") && !strings.HasPrefix(identifier, "GHSA-")) {
			return intelQueryDoneMsg{err: errors.New("use um identificador CWE, CVE ou GHSA")}
		}
		store, err := intelligence.OpenDefault()
		if err != nil {
			return intelQueryDoneMsg{err: err}
		}
		defer store.Close()
		if err := intelligence.SeedCurated(ctx, store); err != nil {
			return intelQueryDoneMsg{err: err}
		}
		if strings.HasPrefix(identifier, "CWE-") {
			description, categories, examples, err := intelligence.Explain(store, ctx, identifier, "")
			if err != nil {
				return intelQueryDoneMsg{err: err}
			}
			lines := []string{identifier}
			for _, line := range strings.Split(description, "\n") {
				lines = append(lines, safePreviewLine(line))
			}
			if len(categories) > 0 {
				lines = append(lines, "", "OWASP mappings: "+safePreviewLine(strings.Join(categories, ", ")))
			}
			for _, example := range examples {
				lines = append(lines, "", "Curated example: "+safePreviewLine(example.Title), safePreviewLine(example.Description))
				for _, reference := range example.References {
					lines = append(lines, "Reference: "+safePreviewLine(reference))
				}
			}
			return intelQueryDoneMsg{title: "Weakness Intelligence · " + identifier, lines: lines}
		}
		advisories, err := store.LookupAll(ctx, identifier)
		if err != nil {
			return intelQueryDoneMsg{err: err}
		}
		if len(advisories) == 0 {
			return intelQueryDoneMsg{err: fmt.Errorf("%s não consta no catálogo local; sincronize a fonte correspondente", identifier)}
		}
		lines := make([]string, 0, len(advisories)*8)
		for index, advisory := range advisories {
			if index > 0 {
				lines = append(lines, "", "---")
			}
			lines = append(lines, safePreviewLine(advisory.ID), "Source: "+safePreviewLine(strings.Join(advisory.Sources, ", ")))
			appendPreviewField(&lines, "Summary: ", advisory.Summary)
			appendPreviewField(&lines, "Details: ", advisory.Details)
			appendPreviewField(&lines, "Severity: ", advisory.Severity)
			if len(advisory.Aliases) > 0 {
				lines = append(lines, "Aliases: "+safePreviewLine(strings.Join(advisory.Aliases, ", ")))
			}
			if len(advisory.Weaknesses) > 0 {
				lines = append(lines, "CWE: "+safePreviewLine(strings.Join(advisory.Weaknesses, ", ")))
			}
			for _, affected := range advisory.Affected {
				packageLine := "Package: " + safePreviewLine(affected.Ecosystem+":"+affected.Name)
				if affected.VersionRange != "" {
					packageLine += " (affected: " + safePreviewLine(affected.VersionRange) + ")"
				}
				if len(affected.FixedVersions) > 0 {
					packageLine += " (fixed: " + safePreviewLine(strings.Join(affected.FixedVersions, ", ")) + ")"
				}
				lines = append(lines, packageLine)
			}
			for _, reference := range advisory.References {
				lines = append(lines, "Reference: "+safePreviewLine(reference))
			}
		}
		return intelQueryDoneMsg{title: "Vulnerability Intelligence · " + identifier, lines: lines}
	}
}

func appendPreviewField(lines *[]string, label, value string) {
	if value == "" {
		return
	}
	for _, line := range strings.Split(value, "\n") {
		*lines = append(*lines, label+safePreviewLine(line))
	}
}

func safePreviewLine(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) && character != '\t' {
			return -1
		}
		return character
	}, value)
}

func intelUpdateCommand(ctx context.Context, target string) tea.Cmd {
	return func() tea.Msg {
		updateCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		store, err := intelligence.OpenDefault()
		if err != nil {
			return intelDoneMsg{err: err, updated: true}
		}
		defer store.Close()
		var updateErr error
		if err := intelligence.SeedCurated(updateCtx, store); err != nil {
			updateErr = errors.Join(updateErr, err)
		}
		if err := (intelligence.CWEConnector{}).Sync(updateCtx, store); err != nil {
			updateErr = errors.Join(updateErr, err)
		}
		if err := (intelligence.KEVConnector{}).Sync(updateCtx, store); err != nil {
			updateErr = errors.Join(updateErr, err)
		}
		discovered, discoverErr := scanner.DiscoverContext(updateCtx, target, scanner.DiscoveryOptions{})
		if discoverErr != nil {
			updateErr = errors.Join(updateErr, fmt.Errorf("descoberta de dependências: %w", discoverErr))
		} else {
			inventory, inventoryErr := intelligence.DiscoverDependencyInventory(discovered.Files)
			if inventoryErr != nil {
				updateErr = errors.Join(updateErr, inventoryErr)
			} else if len(inventory.Dependencies) > 0 {
				if syncErr := (intelligence.OSVConnector{}).SyncPackages(updateCtx, store, inventory.Dependencies); syncErr != nil {
					updateErr = errors.Join(updateErr, syncErr)
				}
			}
		}
		rows, statusErr := store.Sources(updateCtx)
		updateErr = errors.Join(updateErr, statusErr)
		return intelDoneMsg{path: store.Path(), status: rows, err: updateErr, updated: true}
	}
}

func exportCommand(ctx context.Context, report reporter.JSONReport, target, format, destination string) tea.Cmd {
	return func() tea.Msg {
		if err := ctx.Err(); err != nil {
			return exportDoneMsg{err: err}
		}
		path, err := safeExportPath(target, destination)
		if err != nil {
			return exportDoneMsg{err: err}
		}
		info, err := os.Stat(filepath.Dir(path))
		if err != nil || !info.IsDir() {
			return exportDoneMsg{err: errors.New("diretório de destino precisa existir")}
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				err = errors.New("o destino já existe; exportação não sobrescreve arquivos")
			}
			return exportDoneMsg{err: err}
		}
		var writeErr error
		switch format {
		case "json":
			writeErr = reporter.WriteJSON(file, report)
		case "sarif":
			writeErr = reporter.WriteSARIF(file, report.Result)
		default:
			writeErr = errors.New("formato de exportação inválido")
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(path)
			return exportDoneMsg{err: errors.Join(writeErr, closeErr)}
		}
		return exportDoneMsg{}
	}
}

func safeExportPath(target, destination string) (string, error) {
	path, err := filepath.Abs(destination)
	if err != nil {
		return "", errors.New("caminho de exportação inválido")
	}
	root, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", errors.New("não foi possível resolver o projeto analisado")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", errors.New("diretório de exportação precisa existir")
	}
	resolved := filepath.Join(parent, filepath.Base(path))
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", errors.New("exportação fora do projeto analisado é obrigatória")
	}
	return resolved, nil
}

var _ tea.Model = (*Model)(nil)
