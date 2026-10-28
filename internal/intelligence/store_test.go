package intelligence

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mitnick-security/mitnick/internal/scanner"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestOpenMigratesAliasesAndPreservesSharedAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE aliases(alias TEXT PRIMARY KEY COLLATE NOCASE, advisory_id TEXT NOT NULL COLLATE NOCASE REFERENCES advisories(id) ON DELETE CASCADE); CREATE INDEX aliases_advisory_id ON aliases(advisory_id);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var schemaVersion int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", schemaVersion, currentSchemaVersion)
	}
	ctx := context.Background()
	advisories := []Advisory{
		{ID: "GHSA-2222-2222-2222", Source: "github-advisory", Aliases: []string{"CVE-2024-0001"}},
		{ID: "GHSA-2222-2222-2223", Source: "github-advisory", Aliases: []string{"CVE-2024-0001"}},
	}
	if err := store.PutAdvisories(ctx, advisories); err != nil {
		t.Fatal(err)
	}
	got, err := store.LookupAll(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("shared alias resolved to %d advisories, want 2", len(got))
	}
	if err := store.MergeAdvisory(ctx, Advisory{ID: "CVE-2024-0001", Source: "cve-list-v5", Aliases: []string{"CVE-2024-0001"}}); err != nil {
		t.Fatal(err)
	}
	got, err = store.LookupAll(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("ambiguous CVE merge chose an arbitrary advisory: got %d records, want 3", len(got))
	}
}

func TestOpenRejectsNewerSchemaWithoutChangingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "não é suportada") {
		t.Fatalf("future schema was not rejected: %v", err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 99 {
		t.Fatalf("rejected catalog schema changed to %d", version)
	}
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sources'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatal("opening an unsupported schema created application tables")
	}
}

func TestMergeAdvisoryKeepsMultipleRecordsFromOneSource(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	if err := store.MergeAdvisory(ctx, Advisory{ID: "CVE-2024-0001", Source: "cve-list-v5", RawSource: []byte(`{"cveId":"CVE-2024-0001"}`)}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"GHSA-2222-2222-2222", "GHSA-2222-2222-2223"} {
		if err := store.MergeAdvisory(ctx, Advisory{ID: id, Source: "github-advisory", Aliases: []string{"CVE-2024-0001"}, RawSource: []byte(`{"ghsa_id":"` + id + `"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.LookupAll(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("canonical CVE lookup returned %d records, want 1", len(got))
	}
	if len(got[0].SourceRecords) != 3 {
		t.Fatalf("source records = %d, want CVE plus two GHSAs", len(got[0].SourceRecords))
	}
	if len(got[0].Aliases) != 2 || !strings.Contains(strings.Join(got[0].Aliases, ","), "GHSA-") {
		t.Fatalf("GHSA aliases not retained: %#v", got[0].Aliases)
	}
	for _, record := range got[0].SourceRecords {
		if record.Source == "github-advisory" && len(record.Raw) == 0 {
			t.Fatalf("raw source missing for %s", record.ID)
		}
	}
}

func TestOpenDoesNotChangeCustomParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are unavailable")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(parent, "catalog.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("custom parent permissions changed to %o", info.Mode().Perm())
	}
	fileInfo, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("catalog permissions = %o, want 600", fileInfo.Mode().Perm())
	}
}

func TestCachedDependencyFindingsPreserveStaleEvidenceAfterFailure(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	manifest := []byte(`{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/ghost":{"version":"1.0.0"}}}`)
	dep := Dependency{Ecosystem: "npm", Name: "ghost", Version: "1.0.0", File: "package-lock.json"}
	advisory := Advisory{ID: "GHSA-2222-2222-2222", Source: "osv", Summary: "Old advisory", Aliases: []string{"CVE-2024-0001"}}
	fetchedAt := time.Now().UTC().Add(-90 * 24 * time.Hour)
	if err := store.CacheQuery(ctx, dep, []Advisory{advisory}, "osv", fetchedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.CacheQueryError(ctx, dep, "osv", "offline", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeCachedDependencies(ctx, store, []scanner.File{{Path: dep.File, Content: manifest}})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Findings) != 1 || analysis.Findings[0].Severity != "info" {
		t.Fatalf("unknown severity was not represented explicitly: %#v", analysis.Findings)
	}
	if !strings.Contains(analysis.Findings[0].Description, "não ausência de risco") {
		t.Fatalf("unknown severity caveat missing: %s", analysis.Findings[0].Description)
	}
	if len(analysis.Coverage) != 1 || analysis.Coverage[0].Stale != 1 || analysis.Coverage[0].Failed != 1 {
		t.Fatalf("stale/error coverage missing: %#v", analysis.Coverage)
	}
	if len(analysis.Warnings) == 0 || !strings.Contains(analysis.Warnings[0], "resultados locais anteriores foram preservados") {
		t.Fatalf("stale evidence warning missing: %#v", analysis.Warnings)
	}
}

func TestCuratedCatalogSeedsCurrentOWASPAndRules(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	if err := SeedCurated(ctx, store); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM risk_categories WHERE id LIKE 'LLM%:2026'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("2026 OWASP GenAI LLM category count = %d, want 10", count)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM risk_categories WHERE id LIKE 'ASI%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 10 {
		t.Fatalf("OWASP Agentic category count = %d, want 10", count)
	}
	var raw string
	if err := store.db.QueryRowContext(ctx, `SELECT document FROM detection_rules WHERE id='WEB002'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rule DetectionRule
	if err := json.Unmarshal([]byte(raw), &rule); err != nil || rule.Engine == "" || rule.Version != RulePackVersion {
		t.Fatalf("invalid seeded rule %q: %#v, err=%v", raw, rule, err)
	}
}
