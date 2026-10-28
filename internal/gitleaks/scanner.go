package gitleaks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/jsonutil"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

const maxReportBytes = 16 << 20
const engineTimeout = 30 * time.Second

type Scanner struct {
	Binary string
	run    commandRunner
}

type commandRunner func(context.Context, string, []string, string, []string) error

type leak struct {
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	StartLine   int    `json:"StartLine"`
	StartColumn int    `json:"StartColumn"`
	EndLine     int    `json:"EndLine"`
	EndColumn   int    `json:"EndColumn"`
}

func (Scanner) Name() string { return "gitleaks" }

func (Scanner) Capabilities() []string { return []string{"secret-detection"} }

func (s Scanner) Scan(ctx context.Context, root string, files []scanner.File) (items []findings.Finding, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binary, err := s.resolveBinary(root)
	if err != nil {
		return nil, err
	}
	workspace, err := os.MkdirTemp("", "mitnick-gitleaks-")
	if err != nil {
		return nil, errors.New("não foi possível criar a área temporária do Gitleaks")
	}
	defer func() {
		if cleanupErr := os.RemoveAll(workspace); cleanupErr != nil {
			err = errors.Join(err, errors.New("não foi possível remover os arquivos temporários do Gitleaks"))
		}
	}()
	source := filepath.Join(workspace, "files")
	if err := os.Mkdir(source, 0o700); err != nil {
		return nil, errors.New("não foi possível preparar os arquivos para o Gitleaks")
	}
	knownFiles, err := stageFiles(ctx, source, files)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report := filepath.Join(workspace, "report.json")
	args := []string{"detect", "--no-git", "--source", source, "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", report, "--redact", "--log-level", "error"}
	run := s.run
	if run == nil {
		run = runCommand
	}
	engineCtx, cancel := context.WithTimeout(ctx, engineTimeout)
	defer cancel()
	if err := run(engineCtx, binary, args, workspace, engineEnvironment(binary, workspace)); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(engineCtx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("Gitleaks excedeu o limite de execução de 30 segundos")
		}
		return nil, errors.New("Gitleaks falhou ao analisar os arquivos descobertos")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reportData, err := readReport(report)
	if err != nil {
		return nil, err
	}
	return parseReport(reportData, source, knownFiles)
}

func parseReport(reportData []byte, source string, knownFiles map[string]bool) ([]findings.Finding, error) {
	if err := jsonutil.RejectDuplicateKeys(reportData); err != nil {
		return nil, errors.New("Gitleaks retornou JSON ambíguo ou inválido")
	}
	if len(strings.TrimSpace(string(reportData))) == 0 || strings.TrimSpace(string(reportData))[0] != '[' {
		return nil, errors.New("Gitleaks retornou um relatório JSON inválido")
	}
	var leaks []leak
	if err := json.Unmarshal(reportData, &leaks); err != nil {
		return nil, errors.New("Gitleaks retornou um relatório JSON inválido")
	}
	var items []findings.Finding
	for _, item := range leaks {
		file, ok := reportFile(source, item.File, knownFiles)
		if !ok || item.StartLine < 1 {
			return nil, errors.New("Gitleaks retornou uma localização fora dos arquivos descobertos")
		}
		ruleID := "GITLEAKS-" + safeRuleID(item.RuleID)
		finding := findings.New(ruleID, "Padrão de segredo detectado por Gitleaks", "Um padrão compatível com credencial foi detectado. A validade do segredo não foi confirmada; nenhum valor foi incluído na evidência.", "code", "high", "high", "suspected", file, item.StartLine, "Segredo potencial detectado; valor mascarado.", "gitleaks", "Revogue ou rotacione a credencial e substitua-a por uma referência a um gerenciador de segredos.")
		finding.Location.Column = positive(item.StartColumn)
		if item.EndLine >= item.StartLine {
			finding.Location.EndLine = positive(item.EndLine)
			if item.EndLine != item.StartLine || item.EndColumn >= item.StartColumn {
				finding.Location.EndColumn = positive(item.EndColumn)
			}
		}
		finding.References = []string{"https://github.com/gitleaks/gitleaks"}
		items = append(items, finding)
	}
	return items, nil
}

func (s Scanner) resolveBinary(root string) (string, error) {
	name := s.Binary
	if name == "" {
		name = "gitleaks"
	}
	binary, err := exec.LookPath(name)
	if err != nil {
		return "", errors.New("Gitleaks solicitado, mas o executável não está disponível no PATH")
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return "", errors.New("não foi possível resolver o executável Gitleaks")
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return "", errors.New("não foi possível resolver o executável Gitleaks")
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("o executável Gitleaks precisa ser um arquivo regular executável")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("não foi possível resolver a pasta do scan")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", errors.New("não foi possível resolver a pasta do scan")
	}
	relative, err := filepath.Rel(root, binary)
	if err != nil || filepath.IsLocal(relative) {
		return "", errors.New("o executável Gitleaks precisa estar fora da pasta analisada")
	}
	return binary, nil
}

func stageFiles(ctx context.Context, root string, files []scanner.File) (map[string]bool, error) {
	if len(files) > scanner.MaxDiscoveredFiles {
		return nil, errors.New("o número de arquivos excede o limite do Gitleaks")
	}
	known := make(map[string]bool, len(files))
	var total int64
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if file.Path == "" || strings.Contains(file.Path, "\\") {
			return nil, errors.New("caminho inválido ao preparar arquivos para o Gitleaks")
		}
		relative := filepath.FromSlash(file.Path)
		if !filepath.IsLocal(relative) || filepath.Clean(relative) == "." {
			return nil, errors.New("caminho fora da pasta do scan ao preparar arquivos para o Gitleaks")
		}
		relative = filepath.Clean(relative)
		slashPath := filepath.ToSlash(relative)
		if strings.EqualFold(slashPath, ".gitleaks.toml") {
			continue
		}
		if len(file.Content) > scanner.MaxFileBytes {
			return nil, errors.New("arquivo acima do limite ao preparar arquivos para o Gitleaks")
		}
		total += int64(len(file.Content))
		if total > scanner.MaxTotalBytes {
			return nil, errors.New("os arquivos excedem o limite total do Gitleaks")
		}
		if known[slashPath] {
			return nil, errors.New("caminho duplicado ao preparar arquivos para o Gitleaks")
		}
		known[slashPath] = true
		destination := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return nil, errors.New("não foi possível preparar a estrutura de arquivos do Gitleaks")
		}
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, errors.New("não foi possível criar um arquivo temporário para o Gitleaks")
		}
		writeErr := writeContext(ctx, output, file.Content)
		closeErr := output.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if writeErr != nil || closeErr != nil {
			return nil, errors.New("não foi possível gravar um arquivo temporário para o Gitleaks")
		}
	}
	return known, nil
}

func writeContext(ctx context.Context, output io.Writer, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := len(data)
		if chunk > 64<<10 {
			chunk = 64 << 10
		}
		written, err := output.Write(data[:chunk])
		if err != nil {
			return err
		}
		if written != chunk {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func engineEnvironment(binary, workspace string) []string {
	environment := []string{"PATH=" + filepath.Dir(binary), "HOME=" + workspace, "USERPROFILE=" + workspace, "XDG_CONFIG_HOME=" + workspace, "TMPDIR=" + workspace, "TEMP=" + workspace, "TMP=" + workspace}
	if runtime.GOOS == "windows" {
		for _, key := range []string{"SystemRoot", "WINDIR"} {
			if value := os.Getenv(key); value != "" {
				environment = append(environment, key+"="+value)
			}
		}
	}
	return environment
}

func runCommand(ctx context.Context, binary string, args []string, directory string, environment []string) error {
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func readReport(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReportBytes {
		return nil, errors.New("Gitleaks não produziu um relatório regular dentro do limite de 16 MiB")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, errors.New("não foi possível ler o relatório do Gitleaks")
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("o relatório do Gitleaks mudou durante a abertura")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxReportBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > maxReportBytes {
		return nil, errors.New("não foi possível ler o relatório do Gitleaks dentro do limite")
	}
	return data, nil
}

func reportFile(root, name string, known map[string]bool) (string, bool) {
	if name == "" || runtime.GOOS != "windows" && strings.Contains(name, "\\") {
		return "", false
	}
	path := filepath.Clean(filepath.FromSlash(name))
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(relative) {
		return "", false
	}
	relative = filepath.ToSlash(filepath.Clean(relative))
	if !known[relative] {
		return "", false
	}
	return relative, true
}

func safeRuleID(value string) string {
	var out strings.Builder
	for _, r := range value {
		if out.Len() >= 64 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			out.WriteRune(r)
		}
	}
	if out.Len() == 0 {
		return "UNKNOWN"
	}
	return out.String()
}

func positive(value int) int {
	if value < 1 {
		return 0
	}
	return value
}

var _ scanner.Scanner = Scanner{}
