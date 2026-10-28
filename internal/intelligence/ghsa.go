package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
)

const githubAdvisoriesURL = "https://api.github.com/advisories"

var ghsaIdentifier = regexp.MustCompile(`(?i)^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$`)

type GHSAConnector struct {
	Client   *http.Client
	Endpoint string
	Token    string
}

type ghsaRecord struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	URL         string `json:"url"`
	HTMLURL     string `json:"html_url"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Published   string `json:"published_at"`
	Updated     string `json:"updated_at"`
	Withdrawn   string `json:"withdrawn_at"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableRange string `json:"vulnerable_version_range"`
		PatchedVersions string `json:"patched_versions"`
		FirstPatched    *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"vulnerabilities"`
	CVSS struct {
		Vector string  `json:"vector_string"`
		Score  float64 `json:"score"`
	} `json:"cvss"`
	CVSSSeverities struct {
		V3 struct {
			Vector string  `json:"vector_string"`
			Score  float64 `json:"score"`
		} `json:"cvss_v3"`
		V4 struct {
			Vector string  `json:"vector_string"`
			Score  float64 `json:"score"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
	CWEs []struct {
		ID string `json:"cwe_id"`
	} `json:"cwes"`
}

func (c GHSAConnector) Sync(ctx context.Context, store *Store, identifier string) error {
	if store == nil {
		return errors.New("catálogo local não configurado")
	}
	identifier = strings.ToUpper(strings.TrimSpace(identifier))
	isGHSA := ghsaIdentifier.MatchString(identifier)
	isCVE := cveIdentifier.MatchString(identifier)
	if !isGHSA && !isCVE {
		return errors.New("GitHub Advisory exige um ID GHSA ou CVE")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = githubAdvisoriesURL
	}
	base, err := url.Parse(endpoint)
	if err != nil || base.Hostname() == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil {
		return errors.New("endpoint GitHub Advisory inválido")
	}
	token := c.Token
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	headers := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	runID, err := store.StartSync(ctx, "github-advisory")
	if err != nil {
		return err
	}
	var records []ghsaRecord
	rawByID := make(map[string][]byte)
	if isGHSA {
		base.Path = strings.TrimRight(base.Path, "/") + "/" + identifier
		data, _, err := fetchJSONWithHeaders(ctx, client, base.String(), 8<<20, headers)
		if err != nil {
			return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", err)
		}
		if err := jsonutil.RejectDuplicateKeys(data); err != nil {
			return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", fmt.Errorf("resposta GHSA com chaves duplicadas: %w", err))
		}
		var record ghsaRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", fmt.Errorf("registro GHSA inválido: %w", err))
		}
		records = []ghsaRecord{record}
		rawByID[strings.ToUpper(record.GHSAID)] = data
	} else {
		for page := 1; page <= 100; page++ {
			query := base.Query()
			query.Set("cve_id", identifier)
			query.Set("per_page", "100")
			query.Set("page", fmt.Sprint(page))
			base.RawQuery = query.Encode()
			data, _, err := fetchJSONWithHeaders(ctx, client, base.String(), 8<<20, headers)
			if err != nil {
				return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", err)
			}
			if err := jsonutil.RejectDuplicateKeys(data); err != nil {
				return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", fmt.Errorf("resposta GHSA com chaves duplicadas: %w", err))
			}
			var rawRecords []json.RawMessage
			if err := json.Unmarshal(data, &rawRecords); err != nil {
				return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", fmt.Errorf("lista de GHSA inválida: %w", err))
			}
			if len(rawRecords) > 100 {
				return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", errors.New("GitHub retornou mais de 100 advisories em uma página"))
			}
			for _, rawRecord := range rawRecords {
				var record ghsaRecord
				if err := json.Unmarshal(rawRecord, &record); err != nil {
					return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", fmt.Errorf("registro GHSA inválido: %w", err))
				}
				records = append(records, record)
				rawByID[strings.ToUpper(record.GHSAID)] = append([]byte(nil), rawRecord...)
			}
			if len(rawRecords) < 100 {
				break
			}
			if page == 100 {
				return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", errors.New("GitHub excedeu o limite de 100 páginas para CVE"))
			}
		}
	}
	var advisories []Advisory
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		validGHSA := ghsaIdentifier.MatchString(strings.ToUpper(record.GHSAID))
		matchesID := !isGHSA || strings.EqualFold(record.GHSAID, identifier)
		matchesCVE := !isCVE || strings.EqualFold(record.CVEID, identifier)
		if !validGHSA || !matchesID || !matchesCVE {
			return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", fmt.Errorf("registro GHSA %q/CVE %q não corresponde à consulta %s (validGHSA=%t, matchesID=%t, matchesCVE=%t)", record.GHSAID, record.CVEID, identifier, validGHSA, matchesID, matchesCVE))
		}
		id := strings.ToUpper(record.GHSAID)
		if seen[id] {
			continue
		}
		seen[id] = true
		advisory, err := normalizeGHSA(record, rawByID[id])
		if err != nil {
			return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", err)
		}
		advisories = append(advisories, advisory)
	}
	for _, advisory := range advisories {
		if err := store.MergeAdvisory(ctx, advisory); err != nil {
			return finishSourceError(ctx, store, runID, "github-advisory", "GitHub REST API 2022-11-28", err)
		}
	}
	state := "ok"
	if len(advisories) == 0 {
		state = "no-data"
	}
	status := SourceStatus{Name: "github-advisory", Version: "GitHub REST API 2022-11-28", State: state, RecordCount: len(advisories), LastSync: time.Now().UTC()}
	return store.FinishSync(ctx, runID, status, "")
}

func normalizeGHSA(record ghsaRecord, raw []byte) (Advisory, error) {
	id := strings.ToUpper(strings.TrimSpace(record.GHSAID))
	if !ghsaIdentifier.MatchString(id) || len(record.Vulnerabilities) > 1000 || len(record.References) > 1000 || len(record.CWEs) > 100 {
		return Advisory{}, errors.New("registro GitHub Advisory inválido ou com listas fora do limite")
	}
	aliases := []string{}
	if record.CVEID != "" {
		if !cveIdentifier.MatchString(strings.ToUpper(record.CVEID)) {
			return Advisory{}, errors.New("registro GitHub Advisory contém CVE inválida")
		}
		aliases = append(aliases, strings.ToUpper(record.CVEID))
	}
	for _, item := range record.Identifiers {
		value := strings.ToUpper(strings.TrimSpace(item.Value))
		if strings.EqualFold(item.Type, "CVE") && !cveIdentifier.MatchString(value) {
			return Advisory{}, errors.New("registro GitHub Advisory contém alias CVE inválido")
		}
		if value != id && (cveIdentifier.MatchString(value) || ghsaIdentifier.MatchString(value)) {
			aliases = append(aliases, value)
		}
	}
	modified := parseSourceTime(record.Updated)
	severity := normalizeGHSASeverity(record.Severity)
	advisory := Advisory{
		ID: id, Source: "github-advisory", Sources: []string{"github-advisory"},
		SourceIDs: map[string]string{"github-advisory": id}, SourceRaw: map[string][]byte{"github-advisory": append([]byte(nil), raw...)},
		Aliases: cleanStrings(aliases), Summary: strings.TrimSpace(record.Summary), Details: strings.TrimSpace(record.Description),
		Severity: severity, Published: parseSourceTime(record.Published), Modified: modified, Withdrawn: record.Withdrawn,
		RawSource: append([]byte(nil), raw...),
	}
	for _, reference := range record.References {
		if validHTTPURL(reference.URL) {
			advisory.References = append(advisory.References, reference.URL)
		}
	}
	for _, reference := range []string{record.URL, record.HTMLURL} {
		if validHTTPURL(reference) {
			advisory.References = append(advisory.References, reference)
		}
	}
	for _, cwe := range record.CWEs {
		id := strings.ToUpper(strings.TrimSpace(cwe.ID))
		if strings.HasPrefix(id, "CWE-") {
			advisory.Weaknesses = append(advisory.Weaknesses, id)
		}
	}
	for _, vulnerability := range record.Vulnerabilities {
		if vulnerability.Package.Name == "" || vulnerability.Package.Ecosystem == "" {
			continue
		}
		affected := AffectedPackage{Ecosystem: vulnerability.Package.Ecosystem, Name: vulnerability.Package.Name, VersionRange: vulnerability.VulnerableRange}
		if vulnerability.PatchedVersions != "" {
			affected.FixedVersions = cleanStrings(strings.Split(vulnerability.PatchedVersions, ","))
		}
		if vulnerability.FirstPatched != nil && vulnerability.FirstPatched.Identifier != "" {
			affected.FixedVersions = cleanStrings(append(affected.FixedVersions, vulnerability.FirstPatched.Identifier))
		}
		advisory.Affected = append(advisory.Affected, affected)
	}
	cvss := record.CVSSSeverities.V4
	if cvss.Score <= 0 {
		cvss = record.CVSSSeverities.V3
	}
	if cvss.Score <= 0 {
		cvss = record.CVSS
	}
	if cvss.Score > 0 {
		if advisory.Severity == "" {
			advisory.Severity = severityFromScore(cvss.Score)
		}
		value := fmt.Sprintf("%.1f", cvss.Score)
		if cvss.Vector != "" {
			value += " " + cvss.Vector
		}
		advisory.Signals = append(advisory.Signals, RiskSignal{Kind: "cvss", Value: value, AsOf: modified, Source: "github-advisory"})
	}
	advisory.References = cleanStrings(advisory.References)
	advisory.Weaknesses = cleanStrings(advisory.Weaknesses)
	return advisory, nil
}

func normalizeGHSASeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return ""
	}
}
