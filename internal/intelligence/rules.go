package intelligence

import (
	"context"
	"strings"

	"github.com/mitnick-security/mitnick/internal/findings"
)

const RulePackVersion = "0.1.0"

type DetectionRule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Languages      []string `json:"languages,omitempty"`
	Engine         string   `json:"engine"`
	Severity       string   `json:"default_severity"`
	Scope          string   `json:"scope"`
	Evidence       string   `json:"evidence"`
	CWE            []string `json:"cwe,omitempty"`
	OWASP          []string `json:"owasp,omitempty"`
	Recommendation string   `json:"recommendation"`
	Limitations    string   `json:"limitations"`
	Version        string   `json:"version"`
}

var compiledRules = []DetectionRule{
	{ID: "SEC001-SEC005", Name: "Credenciais e segredos prováveis", Languages: []string{"generic text"}, Engine: "compiled-secret-patterns", Severity: "varies", Scope: "text files", Evidence: "Padrões locais; valores são mascarados antes de gerar finding.", CWE: []string{"CWE-798"}, Recommendation: "Revogue credenciais reais e use um gerenciador de segredos.", Limitations: "Heurísticas podem omitir formatos novos ou encontrar exemplos e placeholders."},
	{ID: "GITLEAKS-*", Name: "Segredo detectado por Gitleaks opcional", Languages: []string{"generic text"}, Engine: "gitleaks-8.16.0", Severity: "varies", Scope: "arquivos enviados explicitamente a --gitleaks", Evidence: "Regra da versão local de Gitleaks; valores são mascarados.", Recommendation: "Revogue qualquer segredo válido e remova-o do histórico quando apropriado.", Limitations: "Só executa com --gitleaks; binário local roda com permissões do usuário e não é sandbox."},
	{ID: "WEB001", Name: "HTML sem sanitização visível", Languages: []string{"javascript", "typescript"}, Engine: "compiled-patterns", Severity: "high", Scope: "JS/TS linhas", Evidence: "Uso textual de dangerouslySetInnerHTML.", CWE: []string{"CWE-79"}, OWASP: []string{"A05:2025"}, Recommendation: "Evite HTML bruto ou sanitize com uma allowlist mantida.", Limitations: "Não acompanha sanitização ou origem dos dados."},
	{ID: "WEB002", Name: "Execução dinâmica de código", Languages: []string{"javascript", "typescript"}, Engine: "compiled-patterns", Severity: "medium", Scope: "JS/TS linhas", Evidence: "Uso textual de eval ou new Function.", CWE: []string{"CWE-95"}, OWASP: []string{"A05:2025"}, Recommendation: "Substitua avaliação dinâmica por operações explícitas e validadas.", Limitations: "Não modela se a entrada é controlável nem se a avaliação é necessária."},
	{ID: "WEB003", Name: "CORS wildcard", Languages: []string{"javascript", "typescript"}, Engine: "compiled-patterns", Severity: "high", Scope: "JS/TS linhas", Evidence: "Origem CORS wildcard em configuração textual.", Recommendation: "Limite as origens confiáveis necessárias.", Limitations: "Uma origem pública pode ser intencional; não acompanha autenticação ou resposta."},
	{ID: "WEB004", Name: "Validação de certificado TLS desativada", Languages: []string{"javascript", "typescript"}, Engine: "compiled-patterns", Severity: "high", Scope: "JS/TS linhas", Evidence: "rejectUnauthorized: false.", Recommendation: "Habilite verificação TLS e configure autoridades confiáveis.", Limitations: "Identifica somente o padrão textual."},
	{ID: "SUP001", Name: "Chave secreta Supabase em variável pública", Languages: []string{"javascript", "typescript", "generic config"}, Engine: "compiled-patterns", Severity: "critical", Scope: "nomes de variáveis públicas", Evidence: "Nome de variável pública contém service_role ou secret_key.", CWE: []string{"CWE-798"}, Recommendation: "Mantenha secret/service_role no servidor e use publishable no cliente.", Limitations: "Não inspeciona o valor efetivamente configurado."},
	{ID: "SUP002", Name: "Row Level Security desabilitada", Languages: []string{"sql"}, Engine: "compiled-patterns", Severity: "high", Scope: "migrations SQL", Evidence: "Comando DISABLE ROW LEVEL SECURITY.", Recommendation: "Mantenha RLS habilitada e revise policies e grants.", Limitations: "Não acompanha alterações posteriores nem grants."},
	{ID: "SUP003", Name: "Policy RLS sempre permissiva", Languages: []string{"sql"}, Engine: "compiled-patterns", Severity: "high", Scope: "migrations SQL", Evidence: "Condição textual USING/WITH CHECK (true).", Recommendation: "Restrinja a policy ao usuário, tenant ou condição de negócio.", Limitations: "Policies públicas podem ser intencionais e a regra não avalia roles."},
	{ID: "SUP004", Name: "Edge Function sem validação JWT", Languages: []string{"toml"}, Engine: "compiled-patterns", Severity: "high", Scope: "Supabase config.toml", Evidence: "verify_jwt = false.", Recommendation: "Exija JWT ou documente e teste autenticação equivalente.", Limitations: "Não verifica camadas alternativas de autenticação."},
	{ID: "AGENT001", Name: "Instruções concedem autonomia ampla", Languages: []string{"agent instruction files"}, Engine: "compiled-patterns", Severity: "high", Scope: "arquivos de instrução conhecidos", Evidence: "Frases de autorização para comandos sem revisão.", Recommendation: "Exija aprovação humana e limite permissões ao necessário.", Limitations: "Não interpreta o modelo de permissões de cada cliente."},
	{ID: "MCP001", Name: "Servidor MCP inicia shell ou executor", Languages: []string{"json"}, Engine: "compiled-patterns", Severity: "high", Scope: "configurações MCP conhecidas", Evidence: "Comando declara shell, download-execution ou package runner.", Recommendation: "Revise servidor, fixe versão e evite wrappers de shell.", Limitations: "Revisão estática; não executa nem valida o servidor."},
	{ID: "MCP002", Name: "Escopo de arquivos MCP amplo", Languages: []string{"json"}, Engine: "compiled-patterns", Severity: "high", Scope: "configurações MCP conhecidas", Evidence: "Caminho raiz ou home no escopo de arquivos.", Recommendation: "Conceda somente as menores pastas necessárias.", Limitations: "Padrões heurísticos não avaliam o escopo efetivo do servidor."},
	{ID: "GHSA-*", Name: "Advisory em snapshot npm", Languages: []string{"npm"}, Engine: "bundled-advisory-snapshot", Severity: "varies", Scope: "package-lock.json e npm-shrinkwrap.json", Evidence: "Pacote e versão constam em faixa de advisory selecionada.", CWE: []string{"CWE-1395"}, OWASP: []string{"A03:2025"}, Recommendation: "Atualize para uma versão corrigida indicada pela fonte.", Limitations: "Snapshot pequeno; reachability e condições de runtime não são avaliadas."},
	{ID: "SCA-OSV-*", Name: "Advisory retornada pelo OSV", Languages: []string{"npm", "Go", "PyPI", "crates.io", "Packagist", "RubyGems", "NuGet"}, Engine: "osv-querybatch", Severity: "varies", Scope: "manifests com versões resolvidas e cache local", Evidence: "OSV retornou uma advisory para ecossistema, pacote e versão exatos.", Recommendation: "Revise a advisory e atualize para versão corrigida quando disponível.", Limitations: "Cache do projeto; não confirma reachability, uso em runtime ou condições de implantação."},
	{ID: "POLICY-SUPPRESSION", Name: "Supressão inline auditável", Languages: []string{"source comments"}, Engine: "inline-suppression-parser", Severity: "info", Scope: "comentário inline real com justificativa", Evidence: "Comentário mitnick:ignore com ID exato e motivo.", Recommendation: "Revise periodicamente e remova a exceção quando o risco for resolvido.", Limitations: "A justificativa é fornecida pelo repositório e não é verificada automaticamente."},
}

func RuleCatalog() []DetectionRule {
	return append([]DetectionRule(nil), compiledRules...)
}

func SeedRules(ctx context.Context, store *Store) error {
	for _, rule := range compiledRules {
		rule.Version = RulePackVersion
		if err := store.SaveRule(ctx, rule.ID, rule); err != nil {
			return err
		}
	}
	return nil
}

func EnrichFindings(ctx context.Context, store *Store, items []findings.Finding) error {
	for i := range items {
		item := &items[i]
		rule := findRule(item.RuleID)
		if item.Kind == "" {
			if item.Domain == "agent" {
				item.Kind = "agent-risk"
			} else if item.Domain == "code" {
				item.Kind = "code-weakness"
			}
		}
		if rule != nil {
			item.CWEIDs = cleanStrings(append(item.CWEIDs, rule.CWE...))
			item.OWASPIDs = cleanStrings(append(item.OWASPIDs, rule.OWASP...))
			if item.Detector == nil {
				item.Detector = &findings.Detector{Name: rule.Engine, Version: RulePackVersion}
			}
		}
		for _, weakness := range item.CWEIDs {
			categories, err := store.WeaknessCategories(ctx, weakness)
			if err != nil {
				return err
			}
			item.OWASPIDs = append(item.OWASPIDs, categories...)
		}
		item.OWASPIDs = cleanStrings(item.OWASPIDs)
		if item.AssessmentReason == "" && rule != nil {
			item.AssessmentReason = "Finding heurístico; " + rule.Limitations
		}
	}
	return nil
}

func findRule(id string) *DetectionRule {
	for i := range compiledRules {
		rule := &compiledRules[i]
		if rule.ID == id || rule.ID == "SEC001-SEC005" && strings.HasPrefix(id, "SEC") || rule.ID == "GITLEAKS-*" && strings.HasPrefix(id, "GITLEAKS-") || rule.ID == "GHSA-*" && strings.HasPrefix(id, "GHSA-") || rule.ID == "SCA-OSV-*" && strings.HasPrefix(id, "SCA-OSV-") {
			return rule
		}
	}
	return nil
}
