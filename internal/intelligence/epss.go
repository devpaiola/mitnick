package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
)

const epssURL = "https://api.first.org/data/v1/epss"

type EPSSConnector struct {
	Client   *http.Client
	Endpoint string
}

type epssResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		Score      string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

func (c EPSSConnector) Sync(ctx context.Context, store *Store, identifier string) error {
	if store == nil {
		return errors.New("catálogo local não configurado")
	}
	identifier = strings.ToUpper(strings.TrimSpace(identifier))
	if !cveIdentifier.MatchString(identifier) {
		return errors.New("FIRST EPSS exige um ID CVE")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = epssURL
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return errors.New("endpoint FIRST EPSS inválido")
	}
	query := u.Query()
	query.Set("cve", identifier)
	u.RawQuery = query.Encode()
	runID, err := store.StartSync(ctx, "first-epss")
	if err != nil {
		return err
	}
	data, _, err := fetchJSONWithHeaders(ctx, client, u.String(), 2<<20, nil)
	if err != nil {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", err)
	}
	if err := jsonutil.RejectDuplicateKeys(data); err != nil {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", fmt.Errorf("resposta EPSS amb chaves duplicadas: %w", err))
	}
	var response epssResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", fmt.Errorf("resposta EPSS inválida: %w", err))
	}
	if len(response.Data) > 1 {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", errors.New("EPSS retornou mais de um resultado para uma CVE"))
	}
	if len(response.Data) == 0 {
		return store.FinishSync(ctx, runID, SourceStatus{Name: "first-epss", Version: "FIRST EPSS API v1", State: "no-data", LastSync: time.Now().UTC()}, "")
	}
	item := response.Data[0]
	if !strings.EqualFold(item.CVE, identifier) {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", errors.New("ID da resposta EPSS não corresponde à consulta"))
	}
	score, err := strconv.ParseFloat(item.Score, 64)
	if err != nil || score < 0 || score > 1 {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", errors.New("score EPSS fora do intervalo 0..1"))
	}
	percentile, err := strconv.ParseFloat(item.Percentile, 64)
	if err != nil || percentile < 0 || percentile > 1 {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", errors.New("percentil EPSS fora do intervalo 0..1"))
	}
	date, err := time.Parse("2006-01-02", item.Date)
	if err != nil {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", errors.New("data EPSS inválida"))
	}
	value := fmt.Sprintf("score=%.6f; percentile=%.6f", score, percentile)
	advisory := Advisory{
		ID: identifier, Source: "first-epss", Sources: []string{"first-epss"},
		SourceIDs: map[string]string{"first-epss": identifier}, SourceRaw: map[string][]byte{"first-epss": append([]byte(nil), data...)},
		Aliases: []string{identifier}, Signals: []RiskSignal{{Kind: "epss", Value: value, AsOf: date.UTC(), Source: "first-epss"}},
		RawSource: append([]byte(nil), data...),
	}
	if err := store.MergeAdvisory(ctx, advisory); err != nil {
		return finishSourceError(ctx, store, runID, "first-epss", "FIRST EPSS API v1", err)
	}
	status := SourceStatus{Name: "first-epss", Version: "FIRST EPSS API v1", State: "ok", RecordCount: 1, LastSync: time.Now().UTC()}
	return store.FinishSync(ctx, runID, status, "")
}
