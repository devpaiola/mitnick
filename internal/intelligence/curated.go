package intelligence

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path"
	"strings"
)

const CuratedVersion = "mitnick-curated-0.1.0"

//go:embed examples/**
var exampleFiles embed.FS

type weaknessSeed struct {
	id, name, description string
}

type categorySeed struct {
	id, name, url string
}

var curatedWeaknesses = []weaknessSeed{
	{"CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "A entrada permite que um caminho acesse arquivos fora do diretório autorizado."},
	{"CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "Dados controláveis pelo usuário alteram os comandos ou argumentos enviados ao sistema operacional."},
	{"CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Dados não confiáveis são interpretados como conteúdo ativo em uma página web."},
	{"CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Dados não confiáveis alteram a estrutura de um comando SQL."},
	{"CWE-95", "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')", "Dados influenciam diretivas ou conteúdo avaliado dinamicamente como código."},
	{"CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "O uso de algoritmo criptográfico fraco ou obsoleto reduz a proteção oferecida."},
	{"CWE-798", "Use of Hard-coded Credentials", "Credenciais são armazenadas diretamente no código ou em artefatos distribuídos."},
	{"CWE-1104", "Use of Unmaintained Third Party Components", "O software depende de componentes de terceiros que não recebem manutenção."},
	{"CWE-1395", "Dependency on Vulnerable Third-Party Component", "O software depende de um componente de terceiros com vulnerabilidade conhecida."},
}

var curatedCategories = []categorySeed{
	{"A01:2025", "Broken Access Control", "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/"},
	{"A02:2025", "Security Misconfiguration", "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/"},
	{"A03:2025", "Software Supply Chain Failures", "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"},
	{"A04:2025", "Cryptographic Failures", "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/"},
	{"A05:2025", "Injection", "https://owasp.org/Top10/2025/A05_2025-Injection/"},
	{"A06:2025", "Insecure Design", "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/"},
	{"A07:2025", "Authentication Failures", "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/"},
	{"A08:2025", "Software or Data Integrity Failures", "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/"},
	{"A09:2025", "Security Logging & Alerting Failures", "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/"},
	{"A10:2025", "Mishandling of Exceptional Conditions", "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"},
}

var curatedGenAICategories = []categorySeed{
	{"LLM01:2026", "Prompt Injection", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM02:2026", "Sensitive Information Disclosure", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM03:2026", "Excessive Agency", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM04:2026", "Supply Chain", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM05:2026", "Data and Model Poisoning", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM06:2026", "Unbounded Consumption", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM07:2026", "Misinformation", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM08:2026", "Hidden Context Exposure", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM09:2026", "Vector and Embedding Weaknesses", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
	{"LLM10:2026", "Improper Output Handling", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"},
}

var curatedAgenticCategories = []categorySeed{
	{"ASI01", "Agent Goal Hijack", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI02", "Tool Misuse and Exploitation", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI03", "Identity and Privilege Abuse", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI04", "Agentic Supply Chain Vulnerabilities", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI05", "Unexpected Code Execution (RCE)", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI06", "Memory & Context Poisoning", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI07", "Insecure Inter-Agent Communication", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI08", "Cascading Failures", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI09", "Human-Agent Trust Exploitation", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
	{"ASI10", "Rogue Agents", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"},
}

var curatedMappings = []struct{ cwe, owasp, provenance string }{
	{"CWE-78", "A05:2025", "https://top10.owasp.org/2025/A05_2025-Injection/"},
	{"CWE-79", "A05:2025", "https://top10.owasp.org/2025/A05_2025-Injection/"},
	{"CWE-89", "A05:2025", "https://owasp.org/www-project-cheat-sheets/cheatsheets/Query_Parameterization_Cheat_Sheet.html; classificado pelo OWASP Top 10:2025 como Injection"},
	{"CWE-95", "A05:2025", "https://top10.owasp.org/2025/A05_2025-Injection/"},
	{"CWE-1104", "A03:2025", "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"},
	{"CWE-1395", "A03:2025", "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"},
	{"CWE-327", "A04:2025", "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/"},
}

type Example struct {
	ID          string
	Language    string
	Title       string
	Description string
	CWE         string
	OWASP       []string
	Vulnerable  string
	Secure      string
	Test        string
	References  []string
}

var curatedExamples = []Example{
	{ID: "sql-injection-python", Language: "python", Title: "SQL Injection por interpolação", Description: "A entrada HTTP é interpolada no comando SQL. A versão corrigida usa um parâmetro do driver; o marcador exato depende do driver usado.", CWE: "CWE-89", OWASP: []string{"A05:2025"}, Vulnerable: "examples/python/sql-injection/bad.py", Secure: "examples/python/sql-injection/good.py", Test: "examples/python/sql-injection/test.py", References: []string{"https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/www-project-cheat-sheets/cheatsheets/Query_Parameterization_Cheat_Sheet.html"}},
}

func SeedCurated(ctx context.Context, store *Store) error {
	if store == nil {
		return errors.New("catálogo local não configurado")
	}
	for _, category := range curatedCategories {
		if err := store.SaveCategory(ctx, category.id, category.name, "2025", "owasp-top-10", category.url); err != nil {
			return err
		}
	}
	for _, category := range curatedGenAICategories {
		if err := store.SaveCategory(ctx, category.id, category.name, "2026", "owasp-genai-llm-top-10", category.url); err != nil {
			return err
		}
	}
	for _, category := range curatedAgenticCategories {
		if err := store.SaveCategory(ctx, category.id, category.name, "2026", "owasp-genai-agentic-top-10", category.url); err != nil {
			return err
		}
	}
	for _, weakness := range curatedWeaknesses {
		if err := store.SaveWeakness(ctx, weakness.id, weakness.name, weakness.description, "cwe-curated", CuratedVersion); err != nil {
			return err
		}
	}
	for _, mapping := range curatedMappings {
		if err := store.SaveMapping(ctx, mapping.cwe, mapping.owasp, mapping.provenance); err != nil {
			return err
		}
	}
	for _, example := range curatedExamples {
		if err := store.SaveExample(ctx, example.ID, example); err != nil {
			return err
		}
	}
	if err := store.SaveSourceState(ctx, SourceStatus{Name: "cwe-curated", Version: CuratedVersion, State: "bundled", RecordCount: len(curatedWeaknesses)}); err != nil {
		return err
	}
	if err := store.SaveSourceState(ctx, SourceStatus{Name: "owasp-top-10", Version: "2025", State: "bundled", RecordCount: len(curatedCategories)}); err != nil {
		return err
	}
	if err := store.SaveSourceState(ctx, SourceStatus{Name: "owasp-genai-llm-top-10", Version: "2026", State: "bundled", RecordCount: len(curatedGenAICategories)}); err != nil {
		return err
	}
	if err := store.SaveSourceState(ctx, SourceStatus{Name: "owasp-genai-agentic-top-10", Version: "2026", State: "bundled", RecordCount: len(curatedAgenticCategories)}); err != nil {
		return err
	}
	return SeedRules(ctx, store)
}

func Explain(store *Store, ctx context.Context, identifier, language string) (string, []string, []Example, error) {
	identifier = strings.ToUpper(strings.TrimSpace(identifier))
	if !strings.HasPrefix(identifier, "CWE-") {
		return "", nil, nil, errors.New("explain exige um identificador CWE, por exemplo CWE-89")
	}
	name, description, found, err := store.Weakness(ctx, identifier)
	if err != nil {
		return "", nil, nil, err
	}
	if !found {
		return "", nil, nil, fmt.Errorf("%s não está no catálogo local; consulte MITRE CWE ou rode `mitnick intel update --source mitre-cwe`", identifier)
	}
	categories, err := store.WeaknessCategories(ctx, identifier)
	if err != nil {
		return "", nil, nil, err
	}
	var examples []Example
	for _, example := range curatedExamples {
		if !strings.EqualFold(example.CWE, identifier) {
			continue
		}
		if language == "" || strings.EqualFold(example.Language, language) {
			examples = append(examples, example)
		}
	}
	return name + "\n\n" + description, categories, examples, nil
}

func ReadExampleFile(name string) (string, error) {
	clean := path.Clean(strings.TrimPrefix(name, "/"))
	if clean == "." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", errors.New("caminho de exemplo inválido")
	}
	data, err := exampleFiles.ReadFile(clean)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func Examples() []Example {
	return append([]Example(nil), curatedExamples...)
}
