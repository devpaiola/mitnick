package code

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/jsonutil"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

//go:embed advisories.json
var advisoryData []byte

type Scanner struct{}

func (Scanner) Name() string { return "code" }
func (Scanner) Capabilities() []string {
	return []string{"secrets", "web-patterns", "supabase-static-checks", "npm-lockfile-advisories"}
}

func (Scanner) Scan(ctx context.Context, _ string, files []scanner.File) ([]findings.Finding, error) {
	var out []findings.Finding
	var scanErr error
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if isLockfile(file.Path) {
			items, err := scanLockfile(file)
			if err != nil {
				scanErr = errors.Join(scanErr, fmt.Errorf("%s: JSON de lockfile inválido", file.Path))
			} else {
				out = append(out, items...)
			}
		}
		lines := strings.Split(string(file.Content), "\n")
		for i, line := range lines {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			lineNo := i + 1
			out = append(out, scanSecrets(file.Path, lineNo, line)...)
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "*") || strings.EqualFold(filepath.Ext(file.Path), ".sql") && strings.HasPrefix(trim, "--") {
				continue
			}
			out = append(out, scanCodePatterns(file.Path, lineNo, line)...)
			out = append(out, scanSupabasePatterns(file.Path, lineNo, line)...)
		}
	}
	return out, scanErr
}

type advisory struct {
	Ecosystem  string `json:"ecosystem"`
	Package    string `json:"package"`
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
	Summary    string `json:"summary"`
	URL        string `json:"url"`
}

type SnapshotAdvisory struct {
	ID       string   `json:"id"`
	Packages []string `json:"packages"`
	Severity string   `json:"severity"`
	Summary  string   `json:"summary"`
	URL      string   `json:"url"`
}

func SnapshotAdvisories() []SnapshotAdvisory {
	var rows []advisory
	if json.Unmarshal(advisoryData, &rows) != nil {
		return nil
	}
	byID := make(map[string]*SnapshotAdvisory)
	for _, row := range rows {
		item := byID[row.ID]
		if item == nil {
			item = &SnapshotAdvisory{ID: row.ID, Severity: row.Severity, Summary: row.Summary, URL: row.URL}
			byID[row.ID] = item
		}
		item.Packages = append(item.Packages, row.Package)
	}
	out := make([]SnapshotAdvisory, 0, len(byID))
	for _, item := range byID {
		sort.Strings(item.Packages)
		item.Packages = uniqueStrings(item.Packages)
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

type lockPackage struct {
	Version string `json:"version"`
}

type legacyPackage struct {
	Version      string                   `json:"version"`
	Dependencies map[string]legacyPackage `json:"dependencies"`
}

type packageLock struct {
	LockfileVersion int                      `json:"lockfileVersion"`
	Packages        map[string]lockPackage   `json:"packages"`
	Dependencies    map[string]legacyPackage `json:"dependencies"`
}

func isLockfile(name string) bool {
	base := path.Base(name)
	return base == "package-lock.json" || base == "npm-shrinkwrap.json"
}

func scanLockfile(file scanner.File) ([]findings.Finding, error) {
	if err := jsonutil.RejectDuplicateKeys(file.Content); err != nil {
		return nil, errors.New("JSON ambíguo ou inválido")
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(file.Content, &shape) != nil || shape == nil {
		return nil, errors.New("formato JSON não reconhecido")
	}
	if len(shape) == 0 {
		return nil, errors.New("formato JSON de lockfile não reconhecido")
	}
	if raw, ok := shape["lockfileVersion"]; ok {
		var version int
		if json.Unmarshal(raw, &version) != nil || version < 1 || version > 3 {
			return nil, errors.New("versão de lockfile npm não suportada")
		}
	}
	packagesRaw, hasPackages := shape["packages"]
	dependenciesRaw, hasDependencies := shape["dependencies"]
	if !hasPackages && !hasDependencies {
		return nil, errors.New("lockfile não contém packages nem dependencies")
	}
	if hasPackages && bytes.Equal(bytes.TrimSpace(packagesRaw), []byte("null")) || hasDependencies && bytes.Equal(bytes.TrimSpace(dependenciesRaw), []byte("null")) {
		return nil, errors.New("estrutura de dependências do lockfile inválida")
	}
	var lock packageLock
	if err := json.Unmarshal(file.Content, &lock); err != nil {
		return nil, errors.New("formato JSON não reconhecido")
	}
	var advisories []advisory
	if json.Unmarshal(advisoryData, &advisories) != nil {
		return nil, errors.New("base interna de advisories inválida")
	}
	type installedPackage struct{ name, version, path string }
	var installed []installedPackage
	if len(lock.Packages) != 0 {
		for pkgPath, pkg := range lock.Packages {
			if pkgPath == "" || pkg.Version == "" {
				continue
			}
			name := npmNameFromLockPath(pkgPath)
			installed = append(installed, installedPackage{name: name, version: pkg.Version, path: pkgPath})
		}
	} else {
		stack := []map[string]legacyPackage{lock.Dependencies}
		for len(stack) > 0 {
			items := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for name, pkg := range items {
				installed = append(installed, installedPackage{name: name, version: pkg.Version, path: name})
				if len(pkg.Dependencies) != 0 {
					stack = append(stack, pkg.Dependencies)
				}
			}
		}
	}
	tracked := make(map[string]bool, len(advisories))
	for _, adv := range advisories {
		if strings.EqualFold(adv.Ecosystem, "npm") {
			tracked[adv.Package] = true
		}
	}
	var packageLines, legacyPackageLines map[string]int
	lineIndexReady := false
	var out []findings.Finding
	for _, pkg := range installed {
		if !npmName.MatchString(pkg.name) {
			continue
		}
		if !tracked[pkg.name] {
			continue
		}
		if !validNPMVersion(pkg.version) {
			return out, fmt.Errorf("versão inválida para dependência monitorada %s", pkg.name)
		}
		for _, adv := range advisories {
			if adv.Ecosystem != "npm" || pkg.name != adv.Package || compareVersions(pkg.version, adv.Introduced) < 0 || compareVersions(pkg.version, adv.Fixed) >= 0 {
				continue
			}
			if !lineIndexReady {
				packageLines, legacyPackageLines = lockfileKeyLines(file.Content, tracked)
				lineIndexReady = true
			}
			line := 0
			if strings.HasPrefix(pkg.path, "node_modules/") || strings.Contains(pkg.path, "/node_modules/") {
				line = packageLines[pkg.path]
			} else {
				line = legacyPackageLines[pkg.name+"\x00"+pkg.version]
			}
			if line == 0 {
				line = 1
			}
			recommendation := fmt.Sprintf("Atualize %s para uma versão corrigida; o primeiro fix desta faixa é %s. Consulte a advisory para fixes de outras linhas.", pkg.name, adv.Fixed)
			f := findings.New(adv.ID, "Versão em faixa afetada de dependência npm", "A versão registrada consta em um intervalo afetado publicado pela advisory. O scanner não confirma reachability nem as condições de configuração descritas pela fonte. "+adv.Summary, "code", adv.Severity, "high", "validated", file.Path, line, fmt.Sprintf("%s@%s está em um intervalo afetado", pkg.name, pkg.version), "base-local-de-advisories", recommendation)
			f.References = []string{adv.URL}
			out = append(out, f)
		}
	}
	return out, nil
}

func lockfileKeyLines(data []byte, tracked map[string]bool) (map[string]int, map[string]int) {
	packageLines := make(map[string]int)
	legacyPackageLines := make(map[string]int)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	type frame struct {
		kind    json.Delim
		path    []string
		key     string
		keyLine int
		pkgName string
		pkgLine int
		version bool
		wantKey bool
	}
	var stack []frame
	line, scanned := 1, int64(0)
	for {
		token, err := decoder.Token()
		if err == io.EOF || err != nil {
			break
		}
		offset := decoder.InputOffset()
		for scanned < offset {
			if data[scanned] == '\n' {
				line++
			}
			scanned++
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				var childPath []string
				childPackageName, childPackageLine := "", 0
				if len(stack) > 0 {
					parent := &stack[len(stack)-1]
					childPath = append(childPath, parent.path...)
					if parent.kind == '{' && !parent.wantKey {
						if isLegacyDependencyMap(parent.path) {
							childPackageName, childPackageLine = parent.key, parent.keyLine
						}
						childPath = append(childPath, parent.key)
						parent.key = ""
						parent.version = false
						parent.wantKey = true
					}
				}
				stack = append(stack, frame{kind: delim, path: childPath, pkgName: childPackageName, pkgLine: childPackageLine, wantKey: delim == '{'})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
			continue
		}
		if len(stack) == 0 || stack[len(stack)-1].kind != '{' {
			continue
		}
		current := &stack[len(stack)-1]
		if current.wantKey {
			key, ok := token.(string)
			if !ok {
				break
			}
			if len(current.path) == 1 && current.path[0] == "packages" && tracked[npmNameFromLockPath(key)] {
				packageLines[key] = line
			}
			current.key = key
			current.keyLine = line
			current.version = key == "version" && current.pkgName != ""
			current.wantKey = false
		} else {
			if current.version && tracked[current.pkgName] {
				if version, ok := token.(string); ok {
					key := current.pkgName + "\x00" + version
					if _, exists := legacyPackageLines[key]; !exists {
						legacyPackageLines[key] = current.pkgLine
					}
				}
			}
			current.key = ""
			current.version = false
			current.wantKey = true
		}
	}
	return packageLines, legacyPackageLines
}

func npmNameFromLockPath(packagePath string) string {
	name := strings.TrimPrefix(packagePath, "node_modules/")
	if index := strings.LastIndex(name, "/node_modules/"); index >= 0 {
		name = name[index+len("/node_modules/"):]
	}
	return name
}

func isLegacyDependencyMap(objectPath []string) bool {
	if len(objectPath) == 0 || len(objectPath)%2 == 0 || objectPath[0] != "dependencies" {
		return false
	}
	for i := 2; i < len(objectPath); i += 2 {
		if objectPath[i] != "dependencies" {
			return false
		}
	}
	return true
}

func compareVersions(a, b string) int {
	x, xPre, xOK := parseVersion(a)
	y, yPre, yOK := parseVersion(b)
	if !xOK || !yOK {
		return strings.Compare(a, b)
	}
	for i := range x {
		if order := compareNumericIdentifiers(x[i], y[i]); order != 0 {
			return order
		}
	}
	if len(xPre) == 0 && len(yPre) != 0 {
		return 1
	}
	if len(xPre) != 0 && len(yPre) == 0 {
		return -1
	}
	for i := 0; i < len(xPre) && i < len(yPre); i++ {
		xNumeric := numericIdentifier(xPre[i])
		yNumeric := numericIdentifier(yPre[i])
		switch {
		case xNumeric && yNumeric:
			if order := compareNumericIdentifiers(xPre[i], yPre[i]); order != 0 {
				return order
			}
		case xNumeric:
			return -1
		case yNumeric:
			return 1
		default:
			if order := strings.Compare(xPre[i], yPre[i]); order != 0 {
				return order
			}
		}
	}
	if len(xPre) < len(yPre) {
		return -1
	}
	if len(xPre) > len(yPre) {
		return 1
	}
	return 0
}

func parseVersion(value string) ([3]string, []string, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if plus := strings.IndexByte(value, '+'); plus >= 0 {
		value = value[:plus]
	}
	base, pre, hasPre := strings.Cut(value, "-")
	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return [3]string{}, nil, false
	}
	var version [3]string
	for i, part := range parts {
		if !numericIdentifier(part) || len(part) > 1 && part[0] == '0' {
			return [3]string{}, nil, false
		}
		version[i] = part
	}
	if !hasPre {
		return version, nil, true
	}
	identifiers := strings.Split(pre, ".")
	for _, identifier := range identifiers {
		if identifier == "" || !validSemverIdentifier(identifier) || numericIdentifier(identifier) && len(identifier) > 1 && identifier[0] == '0' {
			return [3]string{}, nil, false
		}
	}
	return version, identifiers, true
}

func validNPMVersion(value string) bool {
	if !npmVersion.MatchString(value) {
		return false
	}
	_, _, ok := parseVersion(value)
	return ok
}

func numericIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validSemverIdentifier(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && r != '-' {
			return false
		}
	}
	return true
}

func compareNumericIdentifiers(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

var (
	awsKey            = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	githubToken       = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{40,})\b`)
	slackToken        = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`)
	privateKey        = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	credentialPattern = regexp.MustCompile(`(?i)\b([A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)[A-Za-z0-9_]*)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})`)
	credentialRef     = regexp.MustCompile(`(?i)^(?:process\.env\.[A-Za-z_][A-Za-z0-9_]*|import\.meta\.env\.[A-Za-z_][A-Za-z0-9_]*|os\.(?:getenv|Getenv)\(\s*["'][A-Za-z_][A-Za-z0-9_]*["']\s*\)|Deno\.env\.get\(\s*["'][A-Za-z_][A-Za-z0-9_]*["']\s*\))$`)
	publicSupabaseKey = regexp.MustCompile(`(?i)(?:NEXT_PUBLIC|VITE)_SUPABASE_(?:SERVICE_ROLE(?:_KEY)?|SERVICE_KEY|SECRET_KEY)\b`)
	disableRLS        = regexp.MustCompile(`(?i)\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b`)
	permissiveRLS     = regexp.MustCompile(`(?i)\b(?:USING|WITH\s+CHECK)\s*\(\s*(?:true|1\s*=\s*1)\s*\)`)
	verifyJWTDisabled = regexp.MustCompile(`(?i)^\s*verify_jwt\s*=\s*false\b`)
	dangerousHTML     = regexp.MustCompile(`dangerouslySetInnerHTML`)
	dynamicEval       = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(`)
	wildcardCORS      = regexp.MustCompile(`(?i)access-control-allow-origin.{0,12}["']?\*["']?`)
	insecureTLS       = regexp.MustCompile(`(?i)rejectUnauthorized\s*:\s*false`)
	npmName           = regexp.MustCompile(`^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$`)
	npmVersion        = regexp.MustCompile(`^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
)

func scanSecrets(file string, line int, text string) []findings.Finding {
	type pattern struct {
		re                                  *regexp.Regexp
		id, title, severity, recommendation string
	}
	patterns := []pattern{
		{awsKey, "SEC001", "Chave de acesso AWS exposta", "critical", "Revogue a chave, gere outra e armazene a credencial em um gerenciador de segredos."},
		{githubToken, "SEC002", "Token do GitHub exposto", "critical", "Revogue o token, gere outro e armazene a credencial em um gerenciador de segredos."},
		{slackToken, "SEC003", "Token do Slack exposto", "high", "Revogue o token, gere outro e remova-o do histórico do repositório."},
		{privateKey, "SEC004", "Chave privada no repositório", "critical", "Revogue ou gere outra chave e armazene-a fora do repositório."},
	}
	var out []findings.Finding
	for _, p := range patterns {
		if p.re.MatchString(text) {
			out = append(out, findings.New(p.id, p.title, "Foi encontrado um valor semelhante a uma credencial em um arquivo de texto.", "code", p.severity, "high", "suspected", file, line, "credencial [REDACTED]", "regra-local-de-segredos", p.recommendation))
		}
	}
	if match := credentialPattern.FindStringSubmatch(text); len(match) == 3 && !placeholder(match[2]) && !credentialRef.MatchString(strings.TrimSpace(strings.Trim(match[2], "\"'"))) {
		out = append(out, findings.New("SEC005", "Valor semelhante a credencial no código", "O valor associado a um campo de credencial pode ser um segredo.", "code", "high", "medium", "suspected", file, line, match[1]+"=[REDACTED]", "regra-local-de-segredos", "Se for real, revogue a credencial e carregue-a do ambiente ou de um gerenciador de segredos."))
	}
	return out
}

func placeholder(value string) bool {
	v := strings.ToLower(strings.TrimSpace(strings.Trim(value, "\"'")))
	switch v {
	case "example", "placeholder", "changeme", "change_me", "replace_me", "dummy", "test", "xxxx", "xxxxxxxx", "1234567890", "your_api_key_here":
		return true
	}
	return strings.HasPrefix(v, "your_") || strings.HasPrefix(v, "replace_this_")
}

func scanCodePatterns(file string, line int, text string) []findings.Finding {
	type matchRule struct {
		re                                                    *regexp.Regexp
		id, title, desc, severity, confidence, recommendation string
	}
	rules := []matchRule{{publicSupabaseKey, "SUP001", "Chave secreta do Supabase exposta ao cliente", "O nome de uma chave legada service-role ou secret key aparece em uma variável pública disponível no cliente.", "critical", "high", "Mantenha chaves service-role/secret no servidor; use somente a chave publishable no navegador."}}
	if isJavaScript(filepath.Ext(file)) {
		rules = append(rules,
			matchRule{dangerousHTML, "WEB001", "Renderização de HTML sem sanitização", "dangerouslySetInnerHTML pode transformar entrada não confiável em marcação executável.", "high", "medium", "Evite HTML bruto ou sanitize o conteúdo com um sanitizador mantido e uma allowlist."},
			matchRule{dynamicEval, "WEB002", "Padrão de execução dinâmica de código", "eval ou o construtor Function pode executar uma entrada como código.", "medium", "medium", "Substitua a avaliação dinâmica por operações explícitas e validadas."},
			matchRule{wildcardCORS, "WEB003", "Origem CORS wildcard", "Uma origem CORS wildcard pode expor respostas acessíveis pelo navegador a qualquer site.", "high", "medium", "Limite as origens permitidas aos sites confiáveis necessários pela aplicação."},
			matchRule{insecureTLS, "WEB004", "Verificação de certificado TLS desativada", "Desativar a verificação TLS remove a proteção contra falsificação do endpoint.", "high", "high", "Habilite a verificação de certificados e configure as autoridades confiáveis corretas."},
		)
	}
	var out []findings.Finding
	for _, rule := range rules {
		if rule.re.MatchString(text) {
			out = append(out, findings.New(rule.id, rule.title, rule.desc, "code", rule.severity, rule.confidence, "suspected", file, line, "padrão "+rule.id+" identificado", "regra-estatica-local", rule.recommendation))
		}
	}
	return out
}

func scanSupabasePatterns(file string, line int, text string) []findings.Finding {
	var out []findings.Finding
	if isSupabaseSQL(file) {
		if disableRLS.MatchString(text) {
			out = append(out, findings.New("SUP002", "Row Level Security desabilitada", "A migration desativa RLS em uma tabela Supabase; dados podem ficar acessíveis sem a policy esperada.", "code", "high", "high", "suspected", file, line, "comando DISABLE ROW LEVEL SECURITY", "regra-estatica-supabase", "Mantenha RLS habilitada e revise as policies e grants antes de publicar a migration."))
		}
		if permissiveRLS.MatchString(text) {
			out = append(out, findings.New("SUP003", "Policy RLS usa condição sempre permissiva", "Uma policy Supabase parece aceitar qualquer linha com USING ou WITH CHECK sempre verdadeiro.", "code", "high", "medium", "suspected", file, line, "condição de policy sempre verdadeira", "regra-estatica-supabase", "Restrinja a policy ao usuário, tenant ou condição de negócio apropriada; policies públicas devem ser intencionais."))
		}
	}
	if isSupabaseConfig(file) && verifyJWTDisabled.MatchString(text) {
		out = append(out, findings.New("SUP004", "Edge Function não exige JWT", "A configuração Supabase desativa a validação de JWT para uma Edge Function.", "code", "high", "medium", "suspected", file, line, "verify_jwt = false", "regra-estatica-supabase", "Exija JWT ou documente e teste uma camada de autenticação equivalente."))
	}
	return out
}

func isSupabaseSQL(name string) bool {
	clean := strings.TrimPrefix(strings.ToLower(filepath.ToSlash(filepath.Clean(name))), "./")
	return strings.HasSuffix(clean, ".sql") && strings.Contains("/"+clean, "/supabase/migrations/")
}

func isSupabaseConfig(name string) bool {
	clean := strings.TrimPrefix(strings.ToLower(filepath.ToSlash(filepath.Clean(name))), "./")
	return path.Base(clean) == "config.toml" && strings.Contains("/"+clean, "/supabase/")
}

func isJavaScript(ext string) bool {
	switch strings.ToLower(ext) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return true
	default:
		return false
	}
}
