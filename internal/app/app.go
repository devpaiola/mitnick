package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/mitnick-security/mitnick/internal/ai"
	"github.com/mitnick-security/mitnick/internal/code"
	"github.com/mitnick-security/mitnick/internal/config"
	"github.com/mitnick-security/mitnick/internal/core"
	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/intelligence"
	"github.com/mitnick-security/mitnick/internal/jsonutil"
	"github.com/mitnick-security/mitnick/internal/policy"
	"github.com/mitnick-security/mitnick/internal/reporter"
	"github.com/mitnick-security/mitnick/internal/scanner"
	"github.com/mitnick-security/mitnick/internal/tui"
	"github.com/spf13/cobra"
)

var Version = "0.1.0-dev"

type findingsError struct{}

func (findingsError) Error() string { return "há achados no threshold configurado" }

type scanFailureError struct{ message string }

const maxReportBytes = 64 << 20

func (e scanFailureError) Error() string { return e.message }

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 3
	}
	var findingsErr findingsError
	if errors.As(err, &findingsErr) {
		return 1
	}
	var scanFailure scanFailureError
	if errors.As(err, &scanFailure) {
		return 3
	}
	return 2
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	root := &cobra.Command{Use: "mitnick", Short: "Análise local de segurança para código e configurações de agentes", SilenceErrors: true, SilenceUsage: true, Version: Version}
	root.RunE = func(cmd *cobra.Command, _ []string) error {
		if isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd()) {
			return tui.Run(cmd.Context(), os.Stdin, stdout)
		}
		return cmd.Help()
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) { writeRootHelp(cmd.OutOrStdout()) })
	root.SetVersionTemplate("mitnick {{.Version}} (" + runtime.GOOS + "/" + runtime.GOARCH + ")\n")
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(rawCommand("scan [path]", "Analisar código e configurações de agentes", func(cmd *cobra.Command, args []string) error {
		return runScan(cmd.Context(), args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(rawCommand("menu", "Abrir TUI navegável por teclado", func(cmd *cobra.Command, args []string) error {
		if !isatty.IsTerminal(os.Stdin.Fd()) || !isatty.IsTerminal(os.Stdout.Fd()) {
			return tui.ErrRequiresTerminal
		}
		return tui.Run(cmd.Context(), os.Stdin, stdout)
	}))
	root.AddCommand(rawCommand("doctor", "Verificar configuração local e engines disponíveis", func(cmd *cobra.Command, args []string) error {
		return runDoctor(cmd.Context(), args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(rawCommand("config", "Criar ou validar configuração", func(cmd *cobra.Command, args []string) error {
		return runConfig(args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(rawCommand("rules", "Listar regras incluídas", func(cmd *cobra.Command, args []string) error {
		return runRules(args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(rawCommand("intel", "Atualizar e consultar inteligência local", func(cmd *cobra.Command, args []string) error {
		return runIntel(cmd.Context(), args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(rawCommand("ai", "Listar e conectar clientes Codex ou Claude Code", func(cmd *cobra.Command, args []string) error {
		return runAI(cmd.Context(), args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(rawCommand("explain <CWE-ID>", "Consultar uma fraqueza e exemplos locais", func(cmd *cobra.Command, args []string) error {
		return runExplain(cmd.Context(), args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(rawCommand("report <json-report>", "Exibir um relatório JSON salvo", func(cmd *cobra.Command, args []string) error {
		return runReport(args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}))
	root.AddCommand(&cobra.Command{Use: "version", Short: "Exibir versão e plataforma", Args: cobra.NoArgs, Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "mitnick %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	}})
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func writeRootHelp(w io.Writer) {
	fmt.Fprintln(w, `Mitnick — análise local de segurança para código e configurações de agentes

Uso:
  mitnick                 # Abre a TUI em terminal interativo
  mitnick menu
  mitnick scan [caminho] [flags]
  mitnick doctor [--config caminho] [--ai-check]
  mitnick config init [caminho] | validate [caminho]
  mitnick rules list
  mitnick intel update [caminho] | status | show <ID>
  mitnick ai detect | list | connect <codex|claude> | test
  mitnick explain CWE-89 [--lang python]
  mitnick report <relatorio.json> [--format terminal|sarif]
  mitnick version

Opções globais:
  -h, --help      Exibir ajuda
  -v, --version   Exibir versão`)
}

func rawCommand(use, short string, run func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short, DisableFlagParsing: true, Args: cobra.ArbitraryArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
			return cmd.Help()
		}
		return run(cmd, args)
	}}
	cmd.SetHelpFunc(func(command *cobra.Command, _ []string) { writeCommandHelp(command.Name(), command.OutOrStdout()) })
	return cmd
}

func writeCommandHelp(name string, w io.Writer) {
	switch name {
	case "scan":
		fmt.Fprintln(w, `Uso: mitnick scan [caminho] [flags]


Flags:
  --format terminal|json|sarif   Formato do relatório (padrão: terminal)
  --output caminho               Salvar relatório em arquivo
  --fail-on severidade           critical|high|medium|low|info|none
  --config caminho               Ler configuração JSON
  --timeout duração              Limite total do scan
  --exclude padrões              Globs separados por vírgula
  --gitleaks                     Executar Gitleaks instalado nos arquivos descobertos
	  --ai                           Pedir revisão pelo Codex ou Claude Code conectado
	  --ai-consent                   Autorizar envio de findings/contexto sanitizado; pode consumir créditos`)
	case "doctor":
		fmt.Fprintln(w, "Uso: mitnick doctor [--config caminho] [--ai-check]\nVerifica configuração e engines; --ai-check testa a IA sem conteúdo do projeto e pode consumir créditos.")
	case "config":
		fmt.Fprintln(w, "Uso: mitnick config init [caminho] | validate [caminho]")
	case "rules":
		fmt.Fprintln(w, "Uso: mitnick rules list")
	case "intel":
		fmt.Fprintln(w, "Uso: mitnick intel update [caminho] [--id CVE/GHSA] [--source all|osv|mitre-cwe|cisa-kev|cve-list|nvd|github-advisory|first-epss] [--db caminho] | status [--db caminho] | show <ID> [--db caminho]")
		fmt.Fprintln(w, "update sincroniza fontes externas. Um caminho consulta OSV para dependências encontradas; fontes por ID exigem --id. status/show são offline.")
	case "ai":
		fmt.Fprintln(w, "Uso: mitnick ai detect | list | connect <codex|claude> | test")
		fmt.Fprintln(w, "detect/list só consultam o PATH. connect verifica o login local do CLI e salva a seleção. test envia apenas um pedido sem código e pode consumir créditos.")
	case "explain":
		fmt.Fprintln(w, "Uso: mitnick explain CWE-89 [--lang python] [--db caminho]")
	case "report":
		fmt.Fprintln(w, "Uso: mitnick report <relatorio.json> [--format terminal|sarif]")
	default:
		fmt.Fprintf(w, "Uso: mitnick %s\n", name)
	}
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	args = moveLeadingTarget(args)
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "terminal", "formato do relatório")
	output := fs.String("output", "", "destino do relatório")
	failOn := fs.String("fail-on", "", "threshold de severidade")
	configPath := fs.String("config", "", "arquivo de configuração")
	timeoutText := fs.String("timeout", "", "limite total do scan")
	excludeText := fs.String("exclude", "", "padrões de exclusão separados por vírgula")
	gitleaksEnabled := fs.Bool("gitleaks", false, "executar Gitleaks nos arquivos descobertos")
	aiEnabled := fs.Bool("ai", false, "habilitar revisão por modelo")
	aiConsent := fs.Bool("ai-consent", false, "autorizar envio de findings e contexto sanitizado ao CLI selecionado")
	intelDB := fs.String("intel-db", "", "caminho do catálogo local de inteligência")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("o scan aceita um diretório; use `mitnick scan --help`")
	}
	target := "."
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	}
	cfg, _, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	selectedAI := ""
	if *aiEnabled {
		profile, _, found, profileErr := config.LoadAIProfile()
		if profileErr != nil {
			return profileErr
		}
		if found {
			selectedAI = profile.Provider
		}
		if err := config.Validate(cfg); err != nil {
			return err
		}
	}
	if *aiConsent && !*aiEnabled {
		return errors.New("--ai-consent só pode ser usado com --ai")
	}
	if *aiEnabled && selectedAI == "" {
		return errors.New("nenhuma IA conectada; execute `mitnick ai connect codex` ou `mitnick ai connect claude`")
	}
	if *aiEnabled && !*aiConsent {
		return errors.New("--ai exige --ai-consent porque envia findings e contexto sanitizado ao cliente de IA conectado")
	}
	if *failOn != "" {
		cfg.FailOn = *failOn
	}
	if err := config.Validate(cfg); err != nil {
		return err
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if *timeoutText != "" {
		timeout, err = time.ParseDuration(*timeoutText)
		if err != nil || timeout <= 0 || timeout > time.Hour {
			return errors.New("--timeout deve ser positiva e não maior que 1h, como 30s")
		}
	}
	excludes := append([]string(nil), cfg.Exclude...)
	if *excludeText != "" {
		for _, pattern := range strings.Split(*excludeText, ",") {
			if strings.TrimSpace(pattern) != "" {
				excludes = append(excludes, strings.TrimSpace(pattern))
			}
		}
	}
	if err := scanner.ValidateExclusions(excludes, cfg.ExcludeDirs); err != nil {
		return fmt.Errorf("exclusões inválidas: %w", err)
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := core.Scan(scanCtx, target, core.Options{Workers: cfg.Workers, Timeout: timeout, Exclude: excludes, ExcludeDirs: cfg.ExcludeDirs, Gitleaks: *gitleaksEnabled, IntelligencePath: *intelDB})
	if err != nil {
		return err
	}
	reviews := []reporter.AIReview(nil)
	meta := (*reporter.AIMetadata)(nil)
	if *aiEnabled {
		provider := selectedAI
		if len(result.Findings) != 0 && len(result.EngineErrors) == 0 {
			fmt.Fprintf(stderr, "Aviso: findings e contexto sanitizado serão enviados ao %s conectado; destino e custos seguem a conta/configuração desse CLI.\n", provider)
			reviews, err = ai.Review(scanCtx, ai.Options{Provider: provider, ContentConsent: *aiConsent}, result.Findings, result.SourceFiles)
			if err != nil {
				result.EngineErrors = append(result.EngineErrors, "AI review: "+err.Error())
			}
		} else if len(result.Findings) != 0 && len(result.EngineErrors) != 0 {
			result.Warnings = append(result.Warnings, "análise por IA ignorada porque o scan não foi concluído")
		}
		meta = &reporter.AIMetadata{Enabled: true, Provider: provider, PromptVersion: ai.PromptVersion, Consent: *aiConsent}
	}
	result.FinishedAt = time.Now().UTC()
	if *output != "" {
		resolved, err := safeScanOutputPath(target, *output)
		if err != nil {
			return err
		}
		*output = resolved
	}
	if err := writeReport(*format, *output, stdout, reporter.JSONReport{Result: result, AIReviews: reviews, AI: meta}); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(result.EngineErrors) > 0 {
		return scanFailureError{message: "um scanner ou provedor não concluiu; consulte o relatório"}
	}
	for _, f := range result.Findings {
		if policy.MeetsThreshold(f, cfg.FailOn) {
			return findingsError{}
		}
	}
	return nil
}

func moveLeadingTarget(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	target := args[0]
	return append(append([]string(nil), args[1:]...), target)
}

func writeReport(format, destination string, stdout io.Writer, data reporter.JSONReport) error {
	var write func(io.Writer) error
	switch format {
	case "terminal":
		write = func(w io.Writer) error { return reporter.WriteTerminal(w, data.Result, data.AIReviews) }
	case "json":
		write = func(w io.Writer) error { return reporter.WriteJSON(w, data) }
	case "sarif":
		write = func(w io.Writer) error { return reporter.WriteSARIF(w, data.Result) }
	default:
		return fmt.Errorf("formato %q inválido (escolha terminal, json ou sarif)", format)
	}
	var writer io.Writer = stdout
	var file *os.File
	if destination != "" {
		if info, err := os.Lstat(destination); err == nil && !info.Mode().IsRegular() {
			return errors.New("o destino do relatório precisa ser um arquivo regular, não um symlink ou dispositivo")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("não foi possível inspecionar o destino do relatório: %w", err)
		}
		var err error
		file, err = os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return errors.New("o destino do relatório já existe; o Mitnick não sobrescreve arquivos")
			}
			return fmt.Errorf("não foi possível abrir o destino do relatório: %w", err)
		}
		if err = file.Chmod(0o600); err == nil {
			_, err = file.Seek(0, io.SeekStart)
		}
		if err != nil {
			_ = file.Close()
			_ = os.Remove(destination)
			return fmt.Errorf("não foi possível preparar o destino do relatório: %w", err)
		}
		writer = file
	}
	writeErr := write(writer)
	if file == nil {
		return writeErr
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(destination)
		return writeErr
	}
	if syncErr != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("não foi possível sincronizar o relatório: %w", syncErr)
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("não foi possível fechar o relatório: %w", closeErr)
	}
	return nil
}

func safeScanOutputPath(target, destination string) (string, error) {
	path, err := filepath.Abs(destination)
	if err != nil {
		return "", errors.New("destino de relatório inválido")
	}
	root, err := resolvePathWithMissingTail(target)
	if err != nil {
		return "", errors.New("não foi possível resolver a raiz do scan para validar o destino")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", errors.New("o diretório do relatório precisa existir")
	}
	resolved := filepath.Join(parent, filepath.Base(path))
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", errors.New("o relatório precisa ser salvo fora do projeto analisado")
	}
	return resolved, nil
}

func resolvePathWithMissingTail(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(abs)
	var missing []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", resolveErr
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "arquivo de configuração")
	aiCheck := fs.Bool("ai-check", false, "verificar conectividade do provedor de IA")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("uso: mitnick doctor [--config caminho] [--ai-check] [--ai-consent]")
	}
	cfg, name, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Mitnick %s\nPlataforma: %s/%s\nGo: %s\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	if name == "" {
		fmt.Fprintln(stdout, "Configuração: padrões (nenhum arquivo encontrado)")
	} else {
		fmt.Fprintf(stdout, "Configuração: %s (válida)\n", name)
	}
	fmt.Fprintf(stdout, "Scanners incluídos: código (%s), agentes (%s)\n", strings.Join(([]string{"segredos", "padrões-web", "configurações-Supabase", "advisories-npm"}), ", "), strings.Join(([]string{"instruções-de-agentes", "configurações-MCP", "permissões"}), ", "))
	fmt.Fprintf(stdout, "Concorrência: %d workers; timeout: %ds; threshold: %s\n", cfg.Workers, cfg.TimeoutSeconds, cfg.FailOn)
	for _, binary := range []string{"gitleaks", "osv-scanner"} {
		if path, e := exec.LookPath(binary); e == nil {
			if binary == "gitleaks" {
				fmt.Fprintf(stdout, "Engine opcional disponível: %s (%s; execute somente com --gitleaks)\n", binary, filepath.Base(path))
			} else {
				fmt.Fprintf(stdout, "Engine detectada, mas ainda não integrada: %s (%s)\n", binary, filepath.Base(path))
			}
		} else {
			if binary == "gitleaks" {
				fmt.Fprintf(stdout, "Engine opcional indisponível: %s\n", binary)
			} else {
				fmt.Fprintf(stdout, "Engine não integrada e indisponível: %s\n", binary)
			}
		}
	}
	fmt.Fprintln(stdout, "Cobertura de advisories: snapshot npm revisado em 2026-10-25 para lodash, axios, next, React Server Components e minimist; não é feed completo nem consulta rede; consulte docs/advisory-snapshot.md")
	if !*aiCheck {
		fmt.Fprintln(stdout, "Rede: nenhuma chamada realizada")
		return nil
	}
	profile, _, found, profileErr := config.LoadAIProfile()
	if profileErr != nil {
		return profileErr
	}
	if !found {
		return errors.New("nenhuma IA conectada; execute `mitnick ai connect codex` ou `mitnick ai connect claude`")
	}
	if err := config.Validate(cfg); err != nil {
		return err
	}
	if err := ai.Check(ctx, ai.Options{Provider: profile.Provider}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Teste de IA: OK (%s; nenhum conteúdo do projeto foi enviado)\n", profile.Provider)
	fmt.Fprintln(stdout, "O teste pode consumir créditos da conta gerenciada pelo CLI.")
	return nil
}

func runAI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		writeCommandHelp("ai", stdout)
		return nil
	}
	switch args[0] {
	case "detect", "list":
		if len(args) != 1 {
			return errors.New("uso: mitnick ai detect | list")
		}
		return writeAIInventory(stdout)
	case "connect":
		if len(args) != 2 || (args[1] != ai.Codex && args[1] != ai.Claude) {
			return errors.New("uso: mitnick ai connect <codex|claude>")
		}
		provider := args[1]
		if err := ai.Connect(ctx, provider); err != nil {
			return err
		}
		path, err := config.WriteAIProfile(config.AIConfig{Provider: provider})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s conectado. A seleção foi salva em %s; a autenticação continua no CLI.\n", provider, path)
		return nil
	case "test":
		if len(args) != 1 {
			return errors.New("uso: mitnick ai test")
		}
		provider, err := loadAIProvider()
		if err != nil {
			return err
		}
		if provider == "" {
			return errors.New("nenhuma IA conectada; execute `mitnick ai connect codex` ou `mitnick ai connect claude`")
		}
		if err := ai.Check(ctx, ai.Options{Provider: provider}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Teste de %s concluído; nenhum conteúdo do projeto foi enviado. O uso pode consumir créditos.\n", provider)
		return nil
	default:
		return errors.New("uso: mitnick ai detect | list | connect <codex|claude> | test")
	}
}

func loadAIProvider() (string, error) {
	profile, _, found, err := config.LoadAIProfile()
	if err != nil || !found {
		return "", err
	}
	return profile.Provider, nil
}

func writeAIInventory(stdout io.Writer) error {
	selectedAI, err := loadAIProvider()
	if err != nil {
		return err
	}
	installed := make(map[string]string)
	for _, client := range ai.Detect() {
		installed[client.Provider] = client.Binary
	}
	fmt.Fprintln(stdout, "Clientes de IA (nenhum processo de modelo iniciado):")
	for _, provider := range []string{ai.Codex, ai.Claude} {
		label := "Claude Code"
		if provider == ai.Codex {
			label = "Codex CLI"
		}
		path, ok := installed[provider]
		if !ok {
			fmt.Fprintf(stdout, "  %-11s não encontrado no PATH\n", label)
			continue
		}
		state := "disponível"
		if selectedAI == provider {
			state = "selecionado"
		}
		fmt.Fprintf(stdout, "  %-11s %s (%s)\n", label, state, path)
	}
	fmt.Fprintln(stdout, "Use `mitnick ai connect codex` ou `mitnick ai connect claude` para selecionar um CLI autenticado.")
	return nil
}

func runConfig(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("uso: mitnick config init [caminho] | validate [caminho]")
	}
	switch args[0] {
	case "init":
		destination := "mitnick.json"
		if len(args) > 1 {
			destination = args[1]
		}
		if len(args) > 2 {
			return errors.New("config init aceita no máximo um caminho")
		}
		if err := config.WriteExample(destination); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Criado: %s\n", destination)
		return nil
	case "validate":
		configPath := ""
		if len(args) > 1 {
			configPath = args[1]
		}
		if len(args) > 2 {
			return errors.New("config validate aceita no máximo um caminho")
		}
		cfg, name, err := config.Load(configPath)
		if err != nil {
			return err
		}
		if name == "" {
			fmt.Fprintln(stdout, "Configuração padrão válida")
		} else {
			fmt.Fprintf(stdout, "%s é válido (versão %d)\n", name, cfg.Version)
		}
		return nil
	default:
		return fmt.Errorf("ação de configuração desconhecida: %q", args[0])
	}
}

func runRules(args []string, stdout, stderr io.Writer) error {
	args = moveLeadingTarget(args)
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "terminal", "formato terminal ou json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 || fs.Arg(0) != "list" {
		return errors.New("uso: mitnick rules list [--format terminal|json]")
	}
	rules := intelligence.RuleCatalog()
	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(struct {
			Version    string                       `json:"version"`
			Rules      []intelligence.DetectionRule `json:"rules"`
			Advisories []code.SnapshotAdvisory      `json:"bundled_advisories"`
		}{Version: intelligence.RulePackVersion, Rules: rules, Advisories: code.SnapshotAdvisories()})
	}
	if *format != "terminal" {
		return errors.New("--format deve ser terminal ou json")
	}
	fmt.Fprintf(stdout, "Rule pack %s\n", intelligence.RulePackVersion)
	for _, rule := range rules {
		fmt.Fprintf(stdout, "%-18s %-44s severidade=%-8s motor=%s\n", rule.ID, rule.Name, rule.Severity, rule.Engine)
		fmt.Fprintf(stdout, "  Escopo: %s\n  Evidência: %s\n", rule.Scope, rule.Evidence)
		if len(rule.CWE) > 0 {
			fmt.Fprintf(stdout, "  CWE: %s\n", strings.Join(rule.CWE, ", "))
		}
		if len(rule.OWASP) > 0 {
			fmt.Fprintf(stdout, "  OWASP: %s\n", strings.Join(rule.OWASP, ", "))
		}
		fmt.Fprintf(stdout, "  Limitação: %s\n", rule.Limitations)
	}
	fmt.Fprintln(stdout, "Advisories npm embutidas:")
	for _, advisory := range code.SnapshotAdvisories() {
		fmt.Fprintf(stdout, "%-28s %-44s %s\n", advisory.ID, strings.Join(advisory.Packages, ", "), advisory.Summary)
	}
	return nil
}

func runReport(args []string, stdout, stderr io.Writer) error {
	args = moveLeadingTarget(args)
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "terminal", "output format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mitnick report <relatorio.json> [--format terminal|sarif]")
	}
	data, err := readBoundedFile(fs.Arg(0), maxReportBytes)
	if err != nil {
		return fmt.Errorf("não foi possível ler o relatório JSON: %w", err)
	}
	var report reporter.JSONReport
	if err := jsonutil.RejectDuplicateKeys(data); err != nil {
		return fmt.Errorf("não foi possível ler o relatório JSON: %w", err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("não foi possível ler o relatório JSON: %w", err)
	}
	if report.SchemaVersion != findings.SchemaVersion {
		return fmt.Errorf("versão de schema do relatório não suportada: %q", report.SchemaVersion)
	}
	switch *format {
	case "terminal":
		return reporter.WriteTerminal(stdout, report.Result, report.AIReviews)
	case "sarif":
		return reporter.WriteSARIF(stdout, report.Result)
	default:
		return fmt.Errorf("formato não suportado: %q", *format)
	}
}

func runIntel(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		writeCommandHelp("intel", stdout)
		return nil
	}
	switch args[0] {
	case "update":
		return runIntelUpdate(ctx, args[1:], stdout, stderr)
	case "status":
		return runIntelStatus(ctx, args[1:], stdout, stderr)
	case "show":
		return runIntelShow(ctx, args[1:], stdout, stderr)
	default:
		return errors.New("uso: mitnick intel update|status|show")
	}
}

func runIntelUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	args = moveLeadingTarget(args)
	fs := flag.NewFlagSet("intel update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "all", "fonte: all, osv, mitre-cwe, cisa-kev, cve-list, nvd, github-advisory ou first-epss")
	identifier := fs.String("id", "", "ID CVE ou GHSA para fontes sob demanda")
	dbPath := fs.String("db", "", "caminho do catálogo SQLite local")
	timeoutText := fs.String("timeout", "2m", "limite da sincronização")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("intel update aceita no máximo um diretório")
	}
	target := ""
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	}
	validSources := map[string]bool{"all": true, "osv": true, "mitre-cwe": true, "cisa-kev": true, "cve-list": true, "nvd": true, "github-advisory": true, "first-epss": true}
	if !validSources[*source] {
		return errors.New("--source deve ser all, osv, mitre-cwe, cisa-kev, cve-list, nvd, github-advisory ou first-epss")
	}
	if *identifier != "" && *source != "all" && *source != "cve-list" && *source != "nvd" && *source != "github-advisory" && *source != "first-epss" {
		return fmt.Errorf("--id não se aplica à fonte %s", *source)
	}
	if *source == "osv" && target == "" {
		return errors.New("a sincronização OSV por pacote exige um diretório: mitnick intel update <caminho> --source osv")
	}
	needsID := *source == "cve-list" || *source == "nvd" || *source == "github-advisory" || *source == "first-epss"
	if needsID && strings.TrimSpace(*identifier) == "" {
		return fmt.Errorf("a fonte %s exige --id CVE-AAAA-NNNN (ou GHSA para github-advisory)", *source)
	}
	if *identifier != "" {
		*identifier = strings.ToUpper(strings.TrimSpace(*identifier))
		isCVE := strings.HasPrefix(*identifier, "CVE-")
		isGHSA := strings.HasPrefix(*identifier, "GHSA-")
		if !isCVE && !isGHSA {
			return errors.New("--id deve ser um identificador CVE ou GHSA")
		}
		if (*source == "cve-list" || *source == "nvd" || *source == "first-epss") && !isCVE {
			return fmt.Errorf("a fonte %s exige um ID CVE", *source)
		}
	}
	timeout, err := time.ParseDuration(*timeoutText)
	if err != nil || timeout <= 0 || timeout > time.Hour {
		return errors.New("--timeout deve ser positiva e não maior que 1h")
	}
	if target != "" {
		if _, err := os.Stat(target); err != nil {
			return fmt.Errorf("não foi possível acessar o diretório de dependências: %w", err)
		}
	}
	syncCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	store, err := openIntelStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := intelligence.SeedCurated(syncCtx, store); err != nil {
		return fmt.Errorf("não foi possível preparar o catálogo local: %w", err)
	}
	var updateErr error
	if (*source == "all" || *source == "osv") && target != "" {
		discovered, err := scanner.DiscoverContext(syncCtx, target, scanner.DiscoveryOptions{})
		if err != nil {
			updateErr = errors.Join(updateErr, fmt.Errorf("descoberta de dependências: %w", err))
		} else {
			inventory, err := intelligence.DiscoverDependencyInventory(discovered.Files)
			if err != nil {
				updateErr = errors.Join(updateErr, err)
			} else if len(inventory.Dependencies) == 0 {
				fmt.Fprintln(stdout, "OSV: nenhum pacote com versão resolvida em um manifesto suportado")
				for _, warning := range inventory.Warnings {
					fmt.Fprintln(stdout, "Aviso:", warning)
				}
			} else if err := (intelligence.OSVConnector{}).SyncPackages(syncCtx, store, inventory.Dependencies); err != nil {
				updateErr = errors.Join(updateErr, err)
			} else {
				fmt.Fprintf(stdout, "OSV: %d dependências consultadas e cache local atualizado\n", len(inventory.Dependencies))
			}
			for _, warning := range discovered.Warnings {
				fmt.Fprintln(stdout, "Aviso:", warning)
			}
		}
	} else if (*source == "all" || *source == "osv") && target == "" {
		fmt.Fprintln(stdout, "OSV: nenhuma consulta executada; informe um diretório para atualizar o cache das dependências usadas nele")
	}
	if *source == "all" || *source == "mitre-cwe" {
		if err := (intelligence.CWEConnector{}).Sync(syncCtx, store); err != nil {
			updateErr = errors.Join(updateErr, err)
		} else {
			fmt.Fprintln(stdout, "MITRE CWE: catálogo sincronizado")
		}
	}
	if *source == "all" || *source == "cisa-kev" {
		if err := (intelligence.KEVConnector{}).Sync(syncCtx, store); err != nil {
			updateErr = errors.Join(updateErr, err)
		} else {
			fmt.Fprintln(stdout, "CISA KEV: catálogo sincronizado")
		}
	}
	if *source == "all" && *identifier == "" {
		fmt.Fprintln(stdout, "CVE List V5, NVD, GitHub Advisory e FIRST EPSS: consulta sob demanda; use --id CVE/GHSA")
	}
	if *source == "all" || *source == "cve-list" {
		if *identifier != "" && strings.HasPrefix(*identifier, "CVE-") {
			if err := (intelligence.CVEListConnector{}).Sync(syncCtx, store, *identifier); err != nil {
				updateErr = errors.Join(updateErr, err)
			} else {
				fmt.Fprintf(stdout, "CVE List V5: %s sincronizado\n", *identifier)
			}
		} else if *source == "cve-list" {
			return errors.New("a fonte cve-list exige um ID CVE")
		}
	}
	if *source == "all" || *source == "nvd" {
		if *identifier != "" && strings.HasPrefix(*identifier, "CVE-") {
			if err := (intelligence.NVDConnector{}).Sync(syncCtx, store, *identifier); err != nil {
				updateErr = errors.Join(updateErr, err)
			} else {
				fmt.Fprintf(stdout, "NVD: %s sincronizado\n", *identifier)
			}
		} else if *source == "nvd" {
			return errors.New("a fonte nvd exige um ID CVE")
		}
	}
	if *source == "all" || *source == "github-advisory" {
		if *identifier != "" {
			if err := (intelligence.GHSAConnector{}).Sync(syncCtx, store, *identifier); err != nil {
				updateErr = errors.Join(updateErr, err)
			} else {
				fmt.Fprintf(stdout, "GitHub Advisory: %s sincronizado\n", *identifier)
			}
		} else if *source == "github-advisory" {
			return errors.New("a fonte github-advisory exige --id CVE ou GHSA")
		}
	}
	if *source == "all" || *source == "first-epss" {
		if *identifier != "" && strings.HasPrefix(*identifier, "CVE-") {
			if err := (intelligence.EPSSConnector{}).Sync(syncCtx, store, *identifier); err != nil {
				updateErr = errors.Join(updateErr, err)
			} else {
				fmt.Fprintf(stdout, "FIRST EPSS: %s sincronizado\n", *identifier)
			}
		} else if *source == "first-epss" {
			return errors.New("a fonte first-epss exige um ID CVE")
		}
	}
	if updateErr != nil {
		return fmt.Errorf("sincronização incompleta: %w", updateErr)
	}
	return nil
}

func runIntelStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("intel status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "caminho do catálogo SQLite local")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("uso: mitnick intel status [--db caminho]")
	}
	store, err := openIntelStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := intelligence.SeedCurated(ctx, store); err != nil {
		return err
	}
	statuses, err := store.Sources(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Catálogo: %s\n", store.Path())
	for _, status := range statuses {
		freshness := "sem sincronização externa"
		if !status.LastSync.IsZero() {
			freshness = fmt.Sprintf("%s atrás (%s UTC)", time.Since(status.LastSync).Round(time.Second), status.LastSync.Format(time.RFC3339))
		}
		fmt.Fprintf(stdout, "%-12s versão=%s estado=%s registros=%d atualização=%s", status.Name, valueOrDash(status.Version), status.State, status.RecordCount, freshness)
		if status.Error != "" {
			fmt.Fprintf(stdout, " erro=%s", status.Error)
		}
		fmt.Fprintln(stdout)
	}
	return nil
}

func runIntelShow(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	args = moveLeadingTarget(args)
	fs := flag.NewFlagSet("intel show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "caminho do catálogo SQLite local")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mitnick intel show <ID> [--db caminho]")
	}
	store, err := openIntelStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	advisories, err := store.LookupAll(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	if len(advisories) == 0 {
		return fmt.Errorf("%s não consta no catálogo local; sincronize a fonte correspondente", fs.Arg(0))
	}
	for i, advisory := range advisories {
		if i > 0 {
			fmt.Fprintln(stdout, "\n---")
		}
		if err := writeAdvisory(stdout, advisory); err != nil {
			return err
		}
	}
	return nil
}

func writeAdvisory(stdout io.Writer, advisory intelligence.Advisory) error {
	fmt.Fprintf(stdout, "%s\nFonte canônica: %s\nFontes preservadas: %s\n", advisory.ID, valueOrDash(advisory.Source), strings.Join(advisory.Sources, ", "))
	for _, sourceRecord := range advisory.SourceRecords {
		fmt.Fprintf(stdout, "Registro de origem: %s:%s\n", sourceRecord.Source, sourceRecord.ID)
	}
	if advisory.Summary != "" {
		fmt.Fprintln(stdout, "Resumo:", advisory.Summary)
	}
	if advisory.Details != "" {
		fmt.Fprintln(stdout, "Detalhes:", advisory.Details)
	}
	if advisory.Severity != "" {
		fmt.Fprintln(stdout, "Gravidade:", advisory.Severity)
	} else {
		fmt.Fprintln(stdout, "Gravidade: não informada")
	}
	if len(advisory.Aliases) > 0 {
		fmt.Fprintln(stdout, "Aliases:", strings.Join(advisory.Aliases, ", "))
	}
	if len(advisory.Weaknesses) > 0 {
		fmt.Fprintln(stdout, "CWE:", strings.Join(advisory.Weaknesses, ", "))
	}
	for _, signal := range advisory.Signals {
		date := "sem data"
		if !signal.AsOf.IsZero() {
			date = signal.AsOf.UTC().Format("2006-01-02")
		}
		fmt.Fprintf(stdout, "Sinal %s: %s (fonte=%s; data=%s)\n", signal.Kind, signal.Value, signal.Source, date)
	}
	for _, affected := range advisory.Affected {
		fmt.Fprintf(stdout, "Pacote: %s:%s", affected.Ecosystem, affected.Name)
		if affected.VersionRange != "" {
			fmt.Fprintf(stdout, " (faixa vulnerável: %s)", affected.VersionRange)
		}
		if len(affected.FixedVersions) > 0 {
			fmt.Fprintf(stdout, " (corrigida: %s)", strings.Join(affected.FixedVersions, ", "))
		}
		fmt.Fprintln(stdout)
	}
	for _, reference := range advisory.References {
		fmt.Fprintln(stdout, "Referência:", reference)
	}
	if !advisory.Modified.IsZero() {
		fmt.Fprintln(stdout, "Modificada:", advisory.Modified.UTC().Format(time.RFC3339))
	}
	return nil
}

func runExplain(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	args = moveLeadingTarget(args)
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	language := fs.String("lang", "", "filtrar exemplos por linguagem")
	dbPath := fs.String("db", "", "caminho do catálogo SQLite local")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mitnick explain CWE-89 [--lang python] [--db caminho]")
	}
	store, err := openIntelStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := intelligence.SeedCurated(ctx, store); err != nil {
		return err
	}
	text, categories, examples, err := intelligence.Explain(store, ctx, fs.Arg(0), *language)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s\n\n", text)
	if len(categories) > 0 {
		fmt.Fprintln(stdout, "Categorias OWASP mapeadas:", strings.Join(categories, ", "))
	} else {
		fmt.Fprintln(stdout, "Categorias OWASP mapeadas: nenhuma relação curada para este CWE")
	}
	if len(examples) == 0 {
		fmt.Fprintln(stdout, "Sem exemplo local para esta fraqueza e linguagem.")
	}
	for _, example := range examples {
		fmt.Fprintf(stdout, "\nExemplo: %s (%s)\n%s\n", example.Title, example.Language, example.Description)
		for _, item := range []struct{ label, file string }{{"Vulnerável", example.Vulnerable}, {"Corrigido", example.Secure}, {"Teste estático", example.Test}} {
			if item.file == "" {
				continue
			}
			content, err := intelligence.ReadExampleFile(item.file)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "\n%s (%s):\n%s", item.label, item.file, content)
			if !strings.HasSuffix(content, "\n") {
				fmt.Fprintln(stdout)
			}
		}
		for _, reference := range example.References {
			fmt.Fprintln(stdout, "Referência:", reference)
		}
		fmt.Fprintln(stdout, "Os exemplos são exibidos como dados e não são executados pelo comando.")
	}
	return nil
}

func openIntelStore(path string) (*intelligence.Store, error) {
	if path == "" {
		return intelligence.OpenDefault()
	}
	return intelligence.Open(path)
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func readBoundedFile(name string, limit int64) ([]byte, error) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("o caminho precisa ser um arquivo regular")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("arquivo excede o limite de %d bytes", limit)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, errors.New("arquivo mudou durante a abertura")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("arquivo excede o limite de %d bytes", limit)
	}
	return data, nil
}
