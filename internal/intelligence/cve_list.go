package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
)

const cveListURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

type CVEListConnector struct {
	Client   *http.Client
	Endpoint string
}

type cveListRecord struct {
	Metadata struct {
		ID            string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Descriptions []struct {
				Language string `json:"lang"`
				Value    string `json:"value"`
			} `json:"descriptions"`
			ProblemTypes []struct {
				Descriptions []struct {
					CWEID       string `json:"cweId"`
					Description string `json:"description"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cna"`
	} `json:"containers"`
}

func (c CVEListConnector) Sync(ctx context.Context, store *Store, identifier string) error {
	identifier = strings.ToUpper(strings.TrimSpace(identifier))
	if !cveIdentifier.MatchString(identifier) {
		return errors.New("CVE List V5 exige um ID no formato CVE-AAAA-NNNN")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		parts := strings.Split(identifier, "-")
		sequence := parts[2]
		group := sequence[:len(sequence)-3] + "xxx"
		endpoint = fmt.Sprintf("%s/%s/%s/%s.json", cveListURL, parts[1], group, identifier)
	}
	runID, err := store.StartSync(ctx, "cve-list-v5")
	if err != nil {
		return err
	}
	data, err := fetchJSON(ctx, client, endpoint, 8<<20)
	if err != nil {
		return finishSourceError(ctx, store, runID, "cve-list-v5", "CVE List V5", err)
	}
	if err := jsonutil.RejectDuplicateKeys(data); err != nil {
		return finishSourceError(ctx, store, runID, "cve-list-v5", "CVE List V5", fmt.Errorf("registro CVE ambíguo: %w", err))
	}
	var record cveListRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return finishSourceError(ctx, store, runID, "cve-list-v5", "CVE List V5", fmt.Errorf("registro CVE inválido: %w", err))
	}
	if !strings.EqualFold(record.Metadata.ID, identifier) || len(record.Containers.CNA.Descriptions) > 1000 {
		return finishSourceError(ctx, store, runID, "cve-list-v5", "CVE List V5", errors.New("ID do registro divergente ou listas fora do limite"))
	}
	var descriptions, weaknesses, references []string
	for _, description := range record.Containers.CNA.Descriptions {
		if strings.EqualFold(description.Language, "en") && description.Value != "" {
			descriptions = append(descriptions, description.Value)
		}
	}
	if len(descriptions) == 0 {
		for _, description := range record.Containers.CNA.Descriptions {
			if description.Value != "" {
				descriptions = append(descriptions, description.Value)
			}
		}
	}
	for _, problem := range record.Containers.CNA.ProblemTypes {
		for _, description := range problem.Descriptions {
			cwe := strings.ToUpper(strings.TrimSpace(description.CWEID))
			if cwe == "" && strings.HasPrefix(strings.ToUpper(description.Description), "CWE-") {
				cwe = strings.ToUpper(strings.Fields(description.Description)[0])
			}
			if strings.HasPrefix(cwe, "CWE-") {
				weaknesses = append(weaknesses, cwe)
			}
		}
	}
	for _, reference := range record.Containers.CNA.References {
		if validHTTPURL(reference.URL) {
			references = append(references, reference.URL)
		}
	}
	modified := parseSourceTime(record.Metadata.DateUpdated)
	published := parseSourceTime(record.Metadata.DatePublished)
	withdrawn := ""
	if strings.EqualFold(record.Metadata.State, "REJECTED") {
		withdrawn = record.Metadata.State
	}
	summary := ""
	if len(descriptions) > 0 {
		summary = descriptions[0]
	}
	advisory := Advisory{
		ID: identifier, Source: "cve-list-v5", Sources: []string{"cve-list-v5"},
		SourceIDs: map[string]string{"cve-list-v5": identifier}, SourceRaw: map[string][]byte{"cve-list-v5": append([]byte(nil), data...)},
		Summary: summary, Published: published, Modified: modified, Withdrawn: withdrawn,
		Aliases: []string{identifier}, References: cleanStrings(references), Weaknesses: cleanStrings(weaknesses), RawSource: append([]byte(nil), data...),
	}
	if err := store.MergeAdvisory(ctx, advisory); err != nil {
		return finishSourceError(ctx, store, runID, "cve-list-v5", "CVE List V5", err)
	}
	status := SourceStatus{Name: "cve-list-v5", Version: "CVE JSON 5.1", State: "ok", RecordCount: 1, LastSync: time.Now().UTC()}
	return store.FinishSync(ctx, runID, status, "")
}

func finishSourceError(ctx context.Context, store *Store, runID int64, source, version string, cause error) error {
	status := SourceStatus{Name: source, Version: version, State: "error", LastSync: time.Now().UTC()}
	_ = store.FinishSync(ctx, runID, status, cause.Error())
	return cause
}
