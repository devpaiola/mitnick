package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
)

const (
	osvQueryBatchURL = "https://api.osv.dev/v1/querybatch"
	maxOSVResponse   = 32 << 20
	osvBatchSize     = 100
)

type OSVConnector struct {
	Client   *http.Client
	Endpoint string
}

// QueryPackages returns OSV results aligned with dependencies. Duplicate
// package/version tuples share one upstream query while retaining their input
// positions in the result.
func (c OSVConnector) QueryPackages(ctx context.Context, dependencies []Dependency) ([][]Advisory, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(dependencies) > MaxQueryDependencies {
		return nil, fmt.Errorf("consulta OSV excede %d dependências", MaxQueryDependencies)
	}
	for _, dependency := range dependencies {
		if strings.TrimSpace(dependency.Ecosystem) == "" || strings.TrimSpace(dependency.Name) == "" || strings.TrimSpace(dependency.Version) == "" {
			return nil, errors.New("consulta OSV contém dependência sem ecossistema, pacote ou versão resolvida")
		}
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = osvQueryBatchURL
	}
	unique := deduplicateDependencies(dependencies)
	uniqueResults := make([][]Advisory, len(unique))
	seenAdvisories := make(map[string]bool)
	var totalAdvisoryBytes int64
	for start := 0; start < len(unique); start += osvBatchSize {
		end := min(start+osvBatchSize, len(unique))
		batch, err := queryBatch(ctx, client, endpoint, unique[start:end])
		if err != nil {
			return nil, err
		}
		for _, advisories := range batch {
			for _, advisory := range advisories {
				key := strings.ToUpper(advisory.ID)
				if seenAdvisories[key] {
					continue
				}
				seenAdvisories[key] = true
				totalAdvisoryBytes += int64(len(advisory.RawSource))
				if len(seenAdvisories) > maxQueryAdvisories || totalAdvisoryBytes > maxQueryAdvisoryBytes {
					return nil, errors.New("consulta OSV excede os limites de registros ou dados normalizados")
				}
			}
		}
		copy(uniqueResults[start:end], batch)
	}
	byKey := make(map[string][]Advisory, len(unique))
	for i, dependency := range unique {
		byKey[dependencyKey(dependency)] = uniqueResults[i]
	}
	results := make([][]Advisory, len(dependencies))
	for i, dependency := range dependencies {
		results[i] = append([]Advisory(nil), byKey[dependencyKey(dependency)]...)
	}
	return results, nil
}

func dependencyKey(dependency Dependency) string {
	return strings.ToLower(dependency.Ecosystem + "\x00" + dependency.Name + "\x00" + dependency.Version)
}

const MaxQueryDependencies = 10000

const (
	maxQueryAdvisories    = 10000
	maxQueryAdvisoryBytes = 64 << 20
)

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
	index     int    `json:"-"`
}

type osvQueryRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQueryResponse struct {
	Results []struct {
		Vulns         []json.RawMessage `json:"vulns"`
		NextPageToken string            `json:"next_page_token"`
	} `json:"results"`
}

type osvRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Versions []string `json:"versions"`
		Ranges   []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific map[string]json.RawMessage `json:"database_specific"`
}

func (c OSVConnector) SyncPackages(ctx context.Context, store *Store, dependencies []Dependency) error {
	if store == nil {
		return errors.New("catálogo local não configurado")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = osvQueryBatchURL
	}
	runID, err := store.StartSync(ctx, "osv")
	if err != nil {
		return err
	}
	started := time.Now().UTC()
	unique := deduplicateDependencies(dependencies)
	var syncErr error
	seenIDs := make(map[string]bool)
	for start := 0; start < len(unique); start += osvBatchSize {
		end := start + osvBatchSize
		if end > len(unique) {
			end = len(unique)
		}
		batch := unique[start:end]
		results, err := queryBatch(ctx, client, endpoint, batch)
		if err != nil {
			syncErr = errors.Join(syncErr, err)
			for _, dep := range batch {
				_ = store.CacheQueryError(ctx, dep, "osv", err.Error(), time.Now().UTC())
			}
			continue
		}
		for index, advisories := range results {
			if index >= len(batch) {
				break
			}
			if err := store.CacheQuery(ctx, batch[index], advisories, "osv", time.Now().UTC()); err != nil {
				syncErr = errors.Join(syncErr, fmt.Errorf("armazenando consulta de %s: %w", batch[index].Name, err))
				continue
			}
			for _, advisory := range advisories {
				seenIDs[strings.ToUpper(advisory.ID)] = true
			}
		}
	}
	status := SourceStatus{Name: "osv", Version: "OSV API querybatch v1", LastSync: time.Now().UTC(), State: "ok", RecordCount: len(seenIDs)}
	if syncErr != nil {
		status.State, status.Error = "partial", syncErr.Error()
	}
	if finishErr := store.FinishSync(ctx, runID, status, ""); finishErr != nil {
		syncErr = errors.Join(syncErr, finishErr)
	}
	if syncErr != nil {
		return fmt.Errorf("sincronização OSV parcial desde %s: %w", started.Format(time.RFC3339), syncErr)
	}
	return nil
}

func deduplicateDependencies(dependencies []Dependency) []Dependency {
	seen := make(map[string]bool, len(dependencies))
	out := make([]Dependency, 0, len(dependencies))
	for _, dep := range dependencies {
		if dep.Ecosystem == "" || dep.Name == "" || dep.Version == "" {
			continue
		}
		key := strings.ToLower(dep.Ecosystem + "\x00" + dep.Name + "\x00" + dep.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dep)
	}
	return out
}

func queryBatch(ctx context.Context, client *http.Client, endpoint string, dependencies []Dependency) ([][]Advisory, error) {
	results := make([][]Advisory, len(dependencies))
	requests := make([]osvQuery, len(dependencies))
	for i, dep := range dependencies {
		requests[i].Package.Name = dep.Name
		requests[i].Package.Ecosystem = dep.Ecosystem
		requests[i].Version = dep.Version
		requests[i].index = i
	}
	for page := 0; len(requests) > 0 && page < 100; page++ {
		response, err := fetchOSVPage(ctx, client, endpoint, requests)
		if err != nil {
			return nil, err
		}
		if len(response.Results) != len(requests) {
			return nil, fmt.Errorf("OSV retornou %d resultados para %d consultas", len(response.Results), len(requests))
		}
		next := make([]osvQuery, 0)
		for i, result := range response.Results {
			for _, raw := range result.Vulns {
				advisory, err := normalizeOSV(raw)
				if err != nil {
					return nil, err
				}
				results[requests[i].index] = appendAdvisory(results[requests[i].index], advisory)
			}
			if result.NextPageToken != "" {
				request := requests[i]
				request.PageToken = result.NextPageToken
				next = append(next, request)
			}
		}
		requests = next
	}
	if len(requests) != 0 {
		return nil, errors.New("OSV excedeu 100 páginas para consulta de dependências")
	}
	return results, nil
}

func fetchOSVPage(ctx context.Context, client *http.Client, endpoint string, requests []osvQuery) (osvQueryResponse, error) {
	payload := osvQueryRequest{Queries: requests}
	body, err := json.Marshal(payload)
	if err != nil {
		return osvQueryResponse{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return osvQueryResponse{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "mitnick-security/mitnick")
		response, err := client.Do(req)
		if err != nil {
			lastErr = errors.New("falha ao consultar a API OSV")
		} else {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, maxOSVResponse+1))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				lastErr = errors.New("resposta OSV incompleta")
			} else if len(data) > maxOSVResponse {
				return osvQueryResponse{}, errors.New("resposta OSV excede 32 MiB")
			} else if response.StatusCode >= 500 || response.StatusCode == http.StatusTooManyRequests {
				lastErr = fmt.Errorf("API OSV respondeu HTTP %d", response.StatusCode)
				if attempt < 2 {
					delay := retryDelay(response.Header.Get("Retry-After"), attempt)
					if err := waitContext(ctx, delay); err != nil {
						return osvQueryResponse{}, err
					}
					continue
				}
			} else if response.StatusCode < 200 || response.StatusCode >= 300 {
				return osvQueryResponse{}, fmt.Errorf("API OSV respondeu HTTP %d", response.StatusCode)
			} else if err := jsonutil.RejectDuplicateKeys(data); err != nil {
				return osvQueryResponse{}, fmt.Errorf("resposta OSV ambígua ou inválida: %w", err)
			} else {
				var parsed osvQueryResponse
				if err := json.Unmarshal(data, &parsed); err != nil {
					return osvQueryResponse{}, fmt.Errorf("resposta OSV inválida: %w", err)
				}
				return parsed, nil
			}
		}
		if attempt < 2 {
			if err := waitContext(ctx, time.Duration(1<<attempt)*time.Second); err != nil {
				return osvQueryResponse{}, err
			}
		}
	}
	return osvQueryResponse{}, lastErr
}

func normalizeOSV(raw []byte) (Advisory, error) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return Advisory{}, errors.New("registro OSV vazio ou excede 4 MiB")
	}
	if err := jsonutil.RejectDuplicateKeys(raw); err != nil {
		return Advisory{}, fmt.Errorf("registro OSV ambíguo: %w", err)
	}
	var record osvRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return Advisory{}, fmt.Errorf("registro OSV inválido: %w", err)
	}
	if strings.TrimSpace(record.ID) == "" || len(record.Affected) > 200 || len(record.References) > 500 {
		return Advisory{}, errors.New("registro OSV sem ID ou com listas fora do limite")
	}
	advisory := Advisory{ID: record.ID, Source: "osv", Sources: []string{"osv"}, SourceIDs: map[string]string{"osv": record.ID}, SourceRaw: map[string][]byte{"osv": append([]byte(nil), raw...)}, Aliases: cleanStrings(record.Aliases), Summary: record.Summary, Details: record.Details, Withdrawn: record.Withdrawn, RawSource: append([]byte(nil), raw...)}
	advisory.Published = parseSourceTime(record.Published)
	advisory.Modified = parseSourceTime(record.Modified)
	for _, reference := range record.References {
		if validHTTPURL(reference.URL) {
			advisory.References = append(advisory.References, reference.URL)
		}
	}
	for _, severity := range record.Severity {
		if strings.Contains(strings.ToUpper(severity.Type), "CVSS") && severity.Score != "" {
			advisory.Signals = append(advisory.Signals, RiskSignal{Kind: "cvss", Value: severity.Score, AsOf: advisory.Modified, Source: "osv"})
			advisory.Severity = severityLabelFromVector(severity.Score)
			break
		}
	}
	for _, affected := range record.Affected {
		if affected.Package.Name == "" || affected.Package.Ecosystem == "" {
			continue
		}
		item := AffectedPackage{Ecosystem: affected.Package.Ecosystem, Name: affected.Package.Name, PURL: affected.Package.PURL, Versions: cleanStrings(affected.Versions)}
		for _, versionRange := range affected.Ranges {
			rangeItem := VersionRange{Type: versionRange.Type}
			for _, event := range versionRange.Events {
				rangeItem.Events = append(rangeItem.Events, RangeEvent{Introduced: event.Introduced, Fixed: event.Fixed, LastAffected: event.LastAffected, Limit: event.Limit})
			}
			item.Ranges = append(item.Ranges, rangeItem)
		}
		advisory.Affected = append(advisory.Affected, item)
	}
	advisory.Weaknesses = extractCWEIDs(record.DatabaseSpecific)
	return advisory, nil
}

func appendAdvisory(items []Advisory, advisory Advisory) []Advisory {
	for i := range items {
		if strings.EqualFold(items[i].ID, advisory.ID) {
			return items
		}
	}
	return append(items, advisory)
}

func extractCWEIDs(values map[string]json.RawMessage) []string {
	var ids []string
	for key, raw := range values {
		if strings.EqualFold(key, "cwe_ids") || strings.EqualFold(key, "cwe") || strings.EqualFold(key, "cwe_id") {
			var multiple []string
			if json.Unmarshal(raw, &multiple) == nil {
				ids = append(ids, multiple...)
				continue
			}
			var single string
			if json.Unmarshal(raw, &single) == nil {
				ids = append(ids, single)
			}
		}
	}
	return cleanStrings(ids)
}

func cleanStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[strings.ToLower(value)] {
			seen[strings.ToLower(value)] = true
			out = append(out, value)
		}
	}
	return out
}

func parseSourceTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed.UTC()
}

func severityLabelFromVector(value string) string {
	value = strings.TrimSpace(value)
	if number, err := strconv.ParseFloat(value, 64); err == nil {
		switch {
		case number >= 9:
			return "critical"
		case number >= 7:
			return "high"
		case number >= 4:
			return "medium"
		case number > 0:
			return "low"
		}
	}
	return ""
}

func retryDelay(value string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 && seconds <= 30 {
		return time.Duration(seconds) * time.Second
	}
	return time.Duration(1<<attempt) * time.Second
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validHTTPURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Hostname() != "" && parsed.User == nil
}
