package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
)

const nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type NVDConnector struct {
	Client   *http.Client
	Endpoint string
	APIKey   string
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID             string `json:"id"`
	Published      string `json:"published"`
	LastModified   string `json:"lastModified"`
	VulnStatus     string `json:"vulnStatus"`
	CISAExploitAdd string `json:"cisaExploitAdd"`
	Descriptions   []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Metrics nvdMetrics `json:"metrics"`
}

type nvdMetrics struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

func (c NVDConnector) Sync(ctx context.Context, store *Store, identifier string) error {
	identifier = strings.ToUpper(strings.TrimSpace(identifier))
	if !cveIdentifier.MatchString(identifier) {
		return errors.New("NVD exige um ID CVE")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = nvdURL
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("endpoint NVD inválido")
	}
	query := u.Query()
	query.Set("cveId", identifier)
	u.RawQuery = query.Encode()
	apiKey := c.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("NVD_API_KEY")
	}
	headers := map[string]string{}
	if apiKey != "" {
		headers["apiKey"] = apiKey
	}
	runID, err := store.StartSync(ctx, "nvd")
	if err != nil {
		return err
	}
	data, _, err := fetchJSONWithHeaders(ctx, client, u.String(), 8<<20, headers)
	if err != nil {
		return finishSourceError(ctx, store, runID, "nvd", "NVD CVE API 2.0", err)
	}
	if err := jsonutil.RejectDuplicateKeys(data); err != nil {
		return finishSourceError(ctx, store, runID, "nvd", "NVD CVE API 2.0", fmt.Errorf("resposta NVD ambígua: %w", err))
	}
	var response nvdResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return finishSourceError(ctx, store, runID, "nvd", "NVD CVE API 2.0", fmt.Errorf("resposta NVD inválida: %w", err))
	}
	if response.TotalResults > 1 || len(response.Vulnerabilities) > 1 {
		return finishSourceError(ctx, store, runID, "nvd", "NVD CVE API 2.0", errors.New("NVD retornou mais de um CVE para ID específico"))
	}
	if len(response.Vulnerabilities) == 0 {
		status := SourceStatus{Name: "nvd", Version: "NVD CVE API 2.0", State: "no-data", RecordCount: 0, LastSync: time.Now().UTC()}
		return store.FinishSync(ctx, runID, status, "")
	}
	record := response.Vulnerabilities[0].CVE
	if !strings.EqualFold(record.ID, identifier) {
		return finishSourceError(ctx, store, runID, "nvd", "NVD CVE API 2.0", errors.New("ID da resposta NVD não corresponde à consulta"))
	}
	var description string
	for _, item := range record.Descriptions {
		if strings.EqualFold(item.Lang, "en") {
			description = item.Value
			break
		}
	}
	if description == "" && len(record.Descriptions) > 0 {
		description = record.Descriptions[0].Value
	}
	var references, weaknesses []string
	for _, reference := range record.References {
		if validHTTPURL(reference.URL) {
			references = append(references, reference.URL)
		}
	}
	for _, weakness := range record.Weaknesses {
		for _, item := range weakness.Description {
			value := strings.ToUpper(strings.TrimSpace(item.Value))
			if strings.HasPrefix(value, "CWE-") {
				weaknesses = append(weaknesses, strings.Fields(value)[0])
			}
		}
	}
	modified, published := parseSourceTime(record.LastModified), parseSourceTime(record.Published)
	advisory := Advisory{ID: identifier, Source: "nvd", Sources: []string{"nvd"}, SourceIDs: map[string]string{"nvd": identifier}, SourceRaw: map[string][]byte{"nvd": append([]byte(nil), data...)}, Summary: description, Published: published, Modified: modified, References: cleanStrings(references), Weaknesses: cleanStrings(weaknesses), RawSource: append([]byte(nil), data...)}
	if score, severity, vector := selectNVDMetric(record.Metrics); score > 0 {
		advisory.Severity = severity
		value := strconv.FormatFloat(score, 'f', 1, 64)
		if vector != "" {
			value += " " + vector
		}
		advisory.Signals = append(advisory.Signals, RiskSignal{Kind: "cvss", Value: value, AsOf: modified, Source: "nvd"})
	}
	if record.CISAExploitAdd != "" {
		date, _ := time.Parse("2006-01-02", record.CISAExploitAdd)
		advisory.Signals = append(advisory.Signals, RiskSignal{Kind: "kev", Value: "CISA KEV entry", AsOf: date.UTC(), Source: "nvd"})
	}
	if strings.EqualFold(record.VulnStatus, "Rejected") {
		advisory.Withdrawn = "rejected"
	}
	if err := store.MergeAdvisory(ctx, advisory); err != nil {
		return finishSourceError(ctx, store, runID, "nvd", "NVD CVE API 2.0", err)
	}
	status := SourceStatus{Name: "nvd", Version: "NVD CVE API 2.0", State: "ok", RecordCount: 1, LastSync: time.Now().UTC()}
	return store.FinishSync(ctx, runID, status, "")
}

func selectNVDMetric(metrics nvdMetrics) (float64, string, string) {
	for _, candidate := range []struct {
		version string
		items   []nvdMetric
	}{{"4.0", metrics.V40}, {"3.1", metrics.V31}, {"3.0", metrics.V30}, {"2.0", metrics.V2}} {
		for _, item := range candidate.items {
			if item.Type != "Primary" || item.CVSSData.BaseScore <= 0 {
				continue
			}
			severity := strings.ToLower(item.CVSSData.BaseSeverity)
			if severity == "" {
				if candidate.version == "2.0" {
					severity = severityFromV2Score(item.CVSSData.BaseScore)
				} else {
					severity = severityFromScore(item.CVSSData.BaseScore)
				}
			}
			return item.CVSSData.BaseScore, severity, item.CVSSData.VectorString
		}
	}
	return 0, "", ""
}

func severityFromV2Score(score float64) string {
	switch {
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

func severityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}
