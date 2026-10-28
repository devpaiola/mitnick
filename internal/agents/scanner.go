package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/jsonutil"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

type Scanner struct{}

func (Scanner) Name() string { return "agents" }
func (Scanner) Capabilities() []string {
	return []string{"agent-instructions", "mcp-configurations", "permission-patterns"}
}

var (
	autonomousInstruction   = regexp.MustCompile(`(?i)(run|execute) (any|all|arbitrary) (shell )?commands? (without|with no) (asking|approval|confirmation)|ignore (all )?(safety|security|previous instructions)|unrestricted (terminal|shell|filesystem)`)
	autonomousInstructionPT = regexp.MustCompile(`(?i)\b(?:execute|executar|rode|rodar)\s+(?:todos|todas|quaisquer|qualquer|arbitrários?)?\s*(?:comandos?|instruções?)\b.{0,80}\bsem\s+(?:pedir|solicitar|aprovação|confirmação|revisão)\b|\bignore\s+(?:todas\s+as\s+)?instruções\s+(?:de\s+segurança\s+)?(?:anteriores|prévias)\b|\b(?:terminal|shell|filesystem)\s+sem\s+restrições\b`)
	shellCommand            = regexp.MustCompile(`(?i)("?command"?\s*:\s*"?(?:sh|bash|zsh|cmd|powershell)(?:\.exe)?"?|\b(?:sh|bash|zsh)\s+-c\b|curl\b.{0,80}\|\s*(?:sh|bash)|\bnpx\s+-y\b|\buvx\b)`)
	broadPath               = regexp.MustCompile(`(?:"(?:/|/home|/Users|C:\\|~)(?:"|/)|"(?:path|directory|root)"\s*:\s*"(?:/|/home|/Users|C:\\\\|~))`)
)

func (Scanner) Scan(ctx context.Context, _ string, files []scanner.File) ([]findings.Finding, error) {
	var out []findings.Finding
	var scanErr error
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return out, errors.Join(scanErr, err)
		}
		base := strings.ToLower(path.Base(file.Path))
		if isMCPConfig(file.Path) {
			var document map[string]json.RawMessage
			if jsonutil.RejectDuplicateKeys(file.Content) != nil || json.Unmarshal(file.Content, &document) != nil || document == nil {
				scanErr = errors.Join(scanErr, fmt.Errorf("%s: JSON de configuração MCP inválido", file.Path))
				continue
			}
		}
		if isInstruction(base) {
			for n, line := range strings.Split(string(file.Content), "\n") {
				if err := ctx.Err(); err != nil {
					return out, errors.Join(scanErr, err)
				}
				if autonomousInstruction.MatchString(line) || autonomousInstructionPT.MatchString(line) {
					out = append(out, findings.New("AGENT001", "Instruções concedem autonomia ampla ao agente", "As instruções parecem autorizar execução de comandos sem aprovação humana.", "agent", "high", "medium", "suspected", file.Path, n+1, "instrução de execução sem revisão", "regra-local-de-agente", "Exija aprovação humana para comandos e limite as permissões do agente à tarefa."))
				}
			}
		}
		if isMCPConfig(file.Path) {
			for n, line := range strings.Split(string(file.Content), "\n") {
				if err := ctx.Err(); err != nil {
					return out, errors.Join(scanErr, err)
				}
				if shellCommand.MatchString(line) {
					out = append(out, findings.New("MCP001", "Servidor MCP inicia shell ou executor de pacotes", "A configuração MCP invoca um shell, baixa conteúdo executável ou usa um executor de pacotes sem versão fixa.", "agent", "high", "medium", "suspected", file.Path, n+1, "declaração de comando do servidor (valor omitido)", "regra-local-de-mcp", "Revise o código do servidor e fixe sua versão; evite wrappers de shell e comandos que baixam e executam conteúdo."))
				}
				if broadPath.MatchString(line) {
					out = append(out, findings.New("MCP002", "Escopo de arquivos MCP possivelmente amplo", "A configuração parece conceder acesso à raiz do filesystem ou à pasta pessoal do usuário.", "agent", "high", "medium", "suspected", file.Path, n+1, "declaração de escopo amplo de arquivos", "regra-local-de-mcp", "Passe ao servidor somente as menores pastas do projeto de que ele precisa."))
				}
			}
		}
	}
	return out, scanErr
}

func isInstruction(base string) bool {
	switch base {
	case "agents.md", "claude.md", "claude.local.md", ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md", "gemini.md":
		return true
	default:
		return strings.HasSuffix(base, ".instructions.md")
	}
}

func isMCPConfig(name string) bool {
	name = strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	base := path.Base(name)
	if base == "mcp.json" || base == ".mcp.json" || base == "mcp_config.json" || base == "claude_desktop_config.json" || base == "mcp-config.json" || base == "gemini-extension.json" {
		return true
	}
	if base == "settings.json" && (name == ".gemini/settings.json" || strings.HasSuffix(name, "/.gemini/settings.json")) {
		return true
	}
	return strings.Contains(name, "/mcp/") && strings.HasSuffix(base, ".json")
}
