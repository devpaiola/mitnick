package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
)

const (
	kevURL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	maxKEVBytes   = 16 << 20
	maxKEVRecords = 50000
)

var cveIdentifier = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type KEVConnector struct {
	Client   *http.Client
	Endpoint string
}

type kevCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID             string   `json:"cveID"`
	VendorProject     string   `json:"vendorProject"`
	Product           string   `json:"product"`
	VulnerabilityName string   `json:"vulnerabilityName"`
	DateAdded         string   `json:"dateAdded"`
	ShortDescription  string   `json:"shortDescription"`
	RequiredAction    string   `json:"requiredAction"`
	DueDate           string   `json:"dueDate"`
	KnownRansomware   string   `json:"knownRansomwareCampaignUse"`
	CWEs              []string `json:"cwes"`
}

func (c KEVConnector) Sync(ctx context.Context, store *Store) error {
	if store == nil {
		return errors.New("catálogo local não configurado")
	}
	runID, err := store.StartSync(ctx, "cisa-kev")
	if err != nil {
		return err
	}
	advisories, status, err := c.FetchCatalog(ctx)
	if err != nil {
		status.State, status.Error = "error", err.Error()
		_ = store.FinishSync(ctx, runID, status, err.Error())
		return err
	}
	for _, advisory := range advisories {
		if err := store.MergeAdvisory(ctx, advisory); err != nil {
			err = fmt.Errorf("importando %s: %w", advisory.ID, err)
			status.State, status.Error = "partial", err.Error()
			_ = store.FinishSync(ctx, runID, status, err.Error())
			return err
		}
	}
	status.RecordCount = len(advisories)
	if err := store.FinishSync(ctx, runID, status, ""); err != nil {
		return err
	}
	return nil
}

// FetchCatalog downloads and validates the current CISA KEV catalog without
// writing it to the local intelligence database.
func (c KEVConnector) FetchCatalog(ctx context.Context) ([]Advisory, SourceStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = kevURL
	}
	status := SourceStatus{Name: "cisa-kev", Version: "CISA KEV JSON", State: "error"}
	data, err := fetchJSON(ctx, client, endpoint, maxKEVBytes)
	if err != nil {
		return nil, status, err
	}
	if err := jsonutil.RejectDuplicateKeys(data); err != nil {
		return nil, status, fmt.Errorf("catálogo KEV ambíguo ou inválido: %w", err)
	}
	var catalog kevCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, status, fmt.Errorf("catálogo KEV inválido: %w", err)
	}
	if strings.TrimSpace(catalog.CatalogVersion) == "" || catalog.Count != len(catalog.Vulnerabilities) || len(catalog.Vulnerabilities) > maxKEVRecords {
		return nil, status, errors.New("catálogo KEV sem versão, com contagem inconsistente ou acima do limite")
	}
	status.Version = catalog.CatalogVersion
	status.RecordCount = len(catalog.Vulnerabilities)
	var advisories []Advisory
	for _, entry := range catalog.Vulnerabilities {
		if !cveIdentifier.MatchString(entry.CVEID) || strings.TrimSpace(entry.ShortDescription) == "" {
			return nil, status, fmt.Errorf("registro KEV inválido para %q", entry.CVEID)
		}
		entryRaw, err := json.Marshal(entry)
		if err != nil {
			return nil, status, err
		}
		dateAdded, _ := time.Parse("2006-01-02", entry.DateAdded)
		advisories = append(advisories, Advisory{
			ID: entry.CVEID, Source: "cisa-kev", Sources: []string{"cisa-kev"},
			SourceIDs: map[string]string{"cisa-kev": entry.CVEID},
			SourceRaw: map[string][]byte{"cisa-kev": entryRaw},
			Summary:   entry.ShortDescription,
			Details:   formatKEVDetails(entry),
			Modified:  dateAdded.UTC(),
			References: []string{
				"https://nvd.nist.gov/vuln/detail/" + entry.CVEID,
				"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			},
			Weaknesses: cleanStrings(entry.CWEs),
			Signals:    []RiskSignal{{Kind: "kev", Value: "known-exploited", AsOf: dateAdded.UTC(), Source: "cisa-kev"}},
		})
	}
	status.State, status.LastSync = "ok", time.Now().UTC()
	return advisories, status, nil
}

func formatKEVDetails(entry kevEntry) string {
	var parts []string
	if entry.VulnerabilityName != "" {
		parts = append(parts, entry.VulnerabilityName)
	}
	if entry.VendorProject != "" || entry.Product != "" {
		parts = append(parts, strings.TrimSpace(entry.VendorProject+" "+entry.Product))
	}
	if entry.RequiredAction != "" {
		parts = append(parts, "Ação: "+entry.RequiredAction)
	}
	if entry.DueDate != "" {
		parts = append(parts, "Prazo CISA: "+entry.DueDate)
	}
	if entry.KnownRansomware != "" {
		parts = append(parts, "Uso em campanhas de ransomware: "+entry.KnownRansomware)
	}
	return strings.Join(parts, ". ")
}

func fetchJSON(ctx context.Context, client *http.Client, endpoint string, maxBytes int64) ([]byte, error) {
	data, _, err := fetchJSONWithHeaders(ctx, client, endpoint, maxBytes, nil)
	return data, err
}

func fetchJSONWithHeaders(ctx context.Context, client *http.Client, endpoint string, maxBytes int64, headers map[string]string) ([]byte, http.Header, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "mitnick-security/mitnick")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		response, err := client.Do(req)
		if err != nil {
			lastErr = errors.New("falha ao consultar fonte remota")
		} else {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				lastErr = errors.New("resposta da fonte incompleta")
			} else if int64(len(data)) > maxBytes {
				return nil, nil, fmt.Errorf("resposta da fonte excede %d bytes", maxBytes)
			} else if response.StatusCode >= 500 || response.StatusCode == http.StatusTooManyRequests {
				lastErr = fmt.Errorf("fonte remota respondeu HTTP %d", response.StatusCode)
				if attempt < 2 {
					if err := waitContext(ctx, retryDelay(response.Header.Get("Retry-After"), attempt)); err != nil {
						return nil, nil, err
					}
					continue
				}
			} else if response.StatusCode < 200 || response.StatusCode >= 300 {
				return nil, nil, fmt.Errorf("fonte remota respondeu HTTP %d", response.StatusCode)
			} else {
				return data, response.Header.Clone(), nil
			}
		}
		if attempt < 2 {
			if err := waitContext(ctx, time.Duration(1<<attempt)*time.Second); err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, lastErr
}
