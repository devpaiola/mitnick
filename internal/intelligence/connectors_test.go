package intelligence

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func fixtureClient(fn func(*http.Request) (int, string, http.Header)) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		status, body, headers := fn(request)
		if headers == nil {
			headers = make(http.Header)
		}
		return &http.Response{
			StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)),
			Request: request, ContentLength: int64(len(body)),
		}, nil
	})}
}

func fixtureJSON(body string) (int, string, http.Header) {
	return http.StatusOK, body, nil
}

func TestOSVConnectorPagesAndCachesExactPackageQuery(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	pages := 0
	client := fixtureClient(func(r *http.Request) (int, string, http.Header) {
		pages++
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected OSV request: %s %s", r.Method, r.URL)
		}
		var request osvQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || len(request.Queries) != 1 {
			t.Fatalf("invalid OSV query batch: %#v, err=%v", request, err)
		}
		if request.Queries[0].Package.Name != "left-pad" || request.Queries[0].Version != "1.0.0" {
			t.Fatalf("OSV query did not use exact dependency: %#v", request.Queries[0])
		}
		if request.Queries[0].PageToken == "" {
			return fixtureJSON(`{"results":[{"vulns":[{"id":"GHSA-2222-2222-2222","aliases":["CVE-2024-0001"],"summary":"first"}],"next_page_token":"next"}]}`)
		}
		if request.Queries[0].PageToken != "next" {
			t.Fatalf("OSV page token = %q", request.Queries[0].PageToken)
		}
		return fixtureJSON(`{"results":[{"vulns":[{"id":"GHSA-2222-2222-2223","summary":"second"}]}]}`)
	})
	dependency := Dependency{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", File: "package-lock.json"}
	if err := (OSVConnector{Client: client, Endpoint: "https://fixture.test/osv"}).SyncPackages(ctx, store, []Dependency{dependency}); err != nil {
		t.Fatal(err)
	}
	if pages != 2 {
		t.Fatalf("OSV pages = %d, want 2", pages)
	}
	advisories, state, found, err := store.CachedAdvisories(ctx, dependency)
	if err != nil {
		t.Fatal(err)
	}
	if !found || len(advisories) != 2 || state.Source != "osv" {
		t.Fatalf("OSV cache result = %#v, %#v, found=%v", advisories, state, found)
	}
}

func TestCWEConnectorImportsVersionedFixture(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	archive := newCWEFixture(t)
	client := fixtureClient(func(*http.Request) (int, string, http.Header) {
		return http.StatusOK, string(archive), nil
	})
	if err := (CWEConnector{Client: client, Endpoint: "https://fixture.test/cwe.zip"}).Sync(ctx, store); err != nil {
		t.Fatal(err)
	}
	name, description, found, err := store.Weakness(ctx, "CWE-89")
	if err != nil || !found || name != "SQL Injection" || description != "Inputs change SQL structure." {
		t.Fatalf("CWE record = %q %q found=%v err=%v", name, description, found, err)
	}
	statuses, err := store.Sources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, status := range statuses {
		if status.Name == "mitre-cwe" && status.Version == "4.19" && status.State == "ok" && status.RecordCount == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("CWE source state missing: %#v", statuses)
	}
}

func TestKEVConnectorMergesKnownExploitationSignal(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	feed := `{"catalogVersion":"2026.10","dateReleased":"2026-10-24T00:00:00.000Z","count":1,"vulnerabilities":[{"cveID":"CVE-2024-0001","vendorProject":"Vendor","product":"Product","vulnerabilityName":"Issue","dateAdded":"2026-10-01","shortDescription":"Known exploited issue","requiredAction":"Apply update","dueDate":"2026-11-01","knownRansomwareCampaignUse":"Unknown","cwes":["CWE-89"]}]}`
	client := fixtureClient(func(*http.Request) (int, string, http.Header) { return fixtureJSON(feed) })
	if err := (KEVConnector{Client: client, Endpoint: "https://fixture.test/kev"}).Sync(ctx, store); err != nil {
		t.Fatal(err)
	}
	advisory, found, err := store.Lookup(ctx, "CVE-2024-0001")
	if err != nil || !found {
		t.Fatalf("lookup = found %v, err=%v", found, err)
	}
	if advisory.Summary != "Known exploited issue" || len(advisory.Signals) != 1 || advisory.Signals[0].Kind != "kev" {
		t.Fatalf("KEV record = %#v", advisory)
	}
}

func TestCVEListConnectorKeepsCVEIdentifiersAndRawRecord(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	fixture := `{"cveMetadata":{"cveId":"CVE-2024-0001","state":"PUBLISHED","datePublished":"2024-01-02T00:00:00Z","dateUpdated":"2024-02-03T00:00:00Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Description"}],"problemTypes":[{"descriptions":[{"cweId":"CWE-89","description":"SQL Injection"}]}],"references":[{"url":"https://example.test/advisory"}]}}}`
	client := fixtureClient(func(*http.Request) (int, string, http.Header) { return fixtureJSON(fixture) })
	if err := (CVEListConnector{Client: client, Endpoint: "https://fixture.test/cve.json"}).Sync(ctx, store, "CVE-2024-0001"); err != nil {
		t.Fatal(err)
	}
	advisory, found, err := store.Lookup(ctx, "CVE-2024-0001")
	if err != nil || !found {
		t.Fatalf("lookup = found %v, err=%v", found, err)
	}
	if advisory.Source != "cve-list-v5" || advisory.Summary != "Description" || len(advisory.Weaknesses) != 1 || advisory.Weaknesses[0] != "CWE-89" {
		t.Fatalf("normalized CVE record = %#v", advisory)
	}
	if !bytes.Contains(advisory.SourceRaw["cve-list-v5"], []byte("CVE-2024-0001")) {
		t.Fatal("raw CVE source record was not retained")
	}
}

func TestNVDConnectorImportsCVSSv4AndCWE(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	client := fixtureClient(func(r *http.Request) (int, string, http.Header) {
		if r.URL.Query().Get("cveId") != "CVE-2024-0001" {
			t.Errorf("NVD cveId query = %q", r.URL.Query().Get("cveId"))
		}
		return fixtureJSON(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","published":"2024-01-02T00:00:00.000Z","lastModified":"2024-02-03T00:00:00.000Z","descriptions":[{"lang":"en","value":"NVD description"}],"weaknesses":[{"description":[{"lang":"en","value":"CWE-89"}]}],"metrics":{"cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/AV:N"}}]}}}]}`)
	})
	if err := (NVDConnector{Client: client, Endpoint: "https://fixture.test/nvd"}).Sync(ctx, store, "CVE-2024-0001"); err != nil {
		t.Fatal(err)
	}
	advisory, found, err := store.Lookup(ctx, "CVE-2024-0001")
	if err != nil || !found {
		t.Fatalf("lookup = found %v, err=%v", found, err)
	}
	if advisory.Severity != "critical" || len(advisory.Weaknesses) != 1 || len(advisory.Signals) != 1 || !strings.Contains(advisory.Signals[0].Value, "9.2") {
		t.Fatalf("normalized NVD record = %#v", advisory)
	}
}

func TestGHSAConnectorNormalizesPatchedVersionsAndCVSS(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	id := "GHSA-2222-2222-2222"
	client := fixtureClient(func(r *http.Request) (int, string, http.Header) {
		if r.URL.Path != "/advisories/"+id || r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") == "" {
			t.Errorf("unexpected GitHub request: %s %#v", r.URL, r.Header)
		}
		body := fmt.Sprintf(`{"ghsa_id":%q,"cve_id":"CVE-2024-0001","url":"https://api.github.com/advisories/%s","html_url":"https://github.com/advisories/%s","summary":"GHSA summary","description":"GHSA details","severity":"high","published_at":"2024-01-02T00:00:00Z","updated_at":"2024-02-03T00:00:00Z","identifiers":[{"type":"GHSA","value":%q},{"type":"CVE","value":"CVE-2024-0001"}],"references":[{"url":"https://example.test/ref"}],"vulnerabilities":[{"package":{"ecosystem":"npm","name":"demo"},"vulnerable_version_range":">= 1.0.0, < 1.2.0","patched_versions":"1.2.0, 1.3.1"}],"cvss_severities":{"cvss_v4":{"vector_string":"CVSS:4.0/AV:N","score":8.9}},"cwes":[{"cwe_id":"CWE-89","name":"SQL Injection"}]}`, id, id, id, id)
		return fixtureJSON(body)
	})
	if err := (GHSAConnector{Client: client, Endpoint: "https://fixture.test/advisories"}).Sync(ctx, store, id); err != nil {
		t.Fatal(err)
	}
	advisory, found, err := store.Lookup(ctx, "CVE-2024-0001")
	if err != nil || !found {
		t.Fatalf("CVE alias lookup = found %v, err=%v", found, err)
	}
	if advisory.Severity != "high" || len(advisory.Affected) != 1 || len(advisory.Affected[0].FixedVersions) != 2 || advisory.Affected[0].FixedVersions[0] != "1.2.0" {
		t.Fatalf("normalized GHSA record = %#v", advisory)
	}
	if len(advisory.SourceRecords) != 1 || advisory.SourceRecords[0].ID != id || !bytes.Contains(advisory.SourceRecords[0].Raw, []byte("patched_versions")) {
		t.Fatalf("raw GHSA source record missing: %#v", advisory.SourceRecords)
	}
}

func TestGHSAConnectorPagesCVESearch(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	charset := "23456789cfghjmpqrvwx"
	makeRecord := func(index int) map[string]any {
		id := "GHSA-2222-2222-22" + string(charset[index/len(charset)]) + string(charset[index%len(charset)])
		return map[string]any{"ghsa_id": id, "cve_id": "CVE-2024-0001", "summary": "page record", "severity": "low"}
	}
	pageOne := make([]map[string]any, 100)
	for i := range pageOne {
		pageOne[i] = makeRecord(i)
	}
	pageTwo, _ := json.Marshal([]map[string]any{makeRecord(100)})
	pageOneData, _ := json.Marshal(pageOne)
	pages := 0
	client := fixtureClient(func(r *http.Request) (int, string, http.Header) {
		pages++
		if r.URL.Query().Get("cve_id") != "CVE-2024-0001" || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("CVE lookup query mismatch: %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("page") == "1" {
			return fixtureJSON(string(pageOneData))
		}
		if r.URL.Query().Get("page") == "2" {
			return fixtureJSON(string(pageTwo))
		}
		t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
		return fixtureJSON(`[]`)
	})
	if err := (GHSAConnector{Client: client, Endpoint: "https://fixture.test/advisories"}).Sync(ctx, store, "CVE-2024-0001"); err != nil {
		t.Fatal(err)
	}
	if pages != 2 {
		t.Fatalf("GitHub pages = %d, want 2", pages)
	}
	advisories, err := store.LookupAll(ctx, "CVE-2024-0001")
	if err != nil || len(advisories) != 1 {
		t.Fatalf("canonical lookup = %d records, err=%v", len(advisories), err)
	}
	if len(advisories[0].SourceRecords) != 101 {
		t.Fatalf("retained GHSA records = %d, want 101", len(advisories[0].SourceRecords))
	}
}

func TestEPSSConnectorStoresDatedProbabilitySignal(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	client := fixtureClient(func(r *http.Request) (int, string, http.Header) {
		if r.URL.Query().Get("cve") != "CVE-2024-0001" {
			t.Errorf("EPSS query = %q", r.URL.RawQuery)
		}
		return fixtureJSON(`{"status":"OK","data":[{"cve":"CVE-2024-0001","epss":"0.123456","percentile":"0.987654","date":"2026-10-24"}]}`)
	})
	if err := (EPSSConnector{Client: client, Endpoint: "https://fixture.test/epss"}).Sync(ctx, store, "CVE-2024-0001"); err != nil {
		t.Fatal(err)
	}
	advisory, found, err := store.Lookup(ctx, "CVE-2024-0001")
	if err != nil || !found || len(advisory.Signals) != 1 {
		t.Fatalf("EPSS lookup = %#v, found=%v, err=%v", advisory, found, err)
	}
	if advisory.Signals[0].Kind != "epss" || !strings.Contains(advisory.Signals[0].Value, "0.123456") || advisory.Signals[0].AsOf.Format("2006-01-02") != "2026-10-24" {
		t.Fatalf("EPSS signal = %#v", advisory.Signals[0])
	}
}

func newCWEFixture(t *testing.T) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	file, err := writer.Create("cwec_v4.19.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte(`<Weakness_Catalog Version="4.19"><Weaknesses><Weakness ID="89" Name="SQL Injection"><Description>Inputs change SQL structure.</Description></Weakness></Weaknesses></Weakness_Catalog>`))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestNVDNoDataDoesNotCreateAdvisory(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	client := fixtureClient(func(*http.Request) (int, string, http.Header) {
		return fixtureJSON(`{"totalResults":0,"vulnerabilities":[]}`)
	})
	if err := (NVDConnector{Client: client, Endpoint: "https://fixture.test/nvd"}).Sync(ctx, store, "CVE-2024-0001"); err != nil {
		t.Fatal(err)
	}
	_, found, err := store.Lookup(ctx, "CVE-2024-0001")
	if err != nil || found {
		t.Fatalf("NVD no-data created a record: found=%v err=%v", found, err)
	}
}

func TestCVEListRejectsWrongRecordID(t *testing.T) {
	store := testStore(t)
	client := fixtureClient(func(*http.Request) (int, string, http.Header) {
		return fixtureJSON(`{"cveMetadata":{"cveId":"CVE-2024-0002","state":"PUBLISHED"},"containers":{"cna":{}}}`)
	})
	err := (CVEListConnector{Client: client, Endpoint: "https://fixture.test/cve.json"}).Sync(context.Background(), store, "CVE-2024-0001")
	if err == nil || !strings.Contains(err.Error(), "divergente") {
		t.Fatalf("wrong CVE response error = %v", err)
	}
	statuses, statusErr := store.Sources(context.Background())
	if statusErr != nil {
		t.Fatal(statusErr)
	}
	if len(statuses) == 0 || statuses[0].State != "error" {
		t.Fatalf("failed source state not recorded: %#v", statuses)
	}
}

func TestRetryDelayBoundsRetryAfter(t *testing.T) {
	if got := retryDelay("31", 1); got != 2*time.Second {
		t.Fatalf("invalid Retry-After got %v", got)
	}
	if got := retryDelay("5", 1); got != 5*time.Second {
		t.Fatalf("Retry-After got %v", got)
	}
}

func TestGHSAEndpointRejectsInvalidUserInformation(t *testing.T) {
	store := testStore(t)
	_, err := url.Parse("https://user:password@fixture.test/advisories")
	if err != nil {
		t.Fatal(err)
	}
	if err := (GHSAConnector{Endpoint: "https://user:password@fixture.test/advisories"}).Sync(context.Background(), store, "GHSA-2222-2222-2222"); err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("userinfo endpoint accepted: %v", err)
	}
}
