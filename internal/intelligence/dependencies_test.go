package intelligence

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mitnick-security/mitnick/internal/scanner"
)

func TestDependencyParsersUseResolvedPinnedVersionsOnly(t *testing.T) {
	files := []scanner.File{
		{Path: "package-lock.json", Content: []byte(`{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/@scope/pkg":{"version":"1.2.3"}}}`)},
		{Path: "requirements.txt", Content: []byte("requests==2.31.0\nflask>=3.0\nunpinned\n")},
		{Path: "Cargo.lock", Content: []byte("[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n")},
		{Path: "composer.lock", Content: []byte(`{"packages":[{"name":"vendor/lib","version":"v2.3.4"}],"packages-dev":[]}`)},
		{Path: "Gemfile.lock", Content: []byte("GEM\n  specs:\n    rack (3.0.9)\n")},
		{Path: "packages.lock.json", Content: []byte(`{"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"13.0.1","resolved":"13.0.1","contentHash":"x"}}}}`)},
		{Path: "go.mod", Content: []byte("module example\nrequire example.com/lib v1.2.3\n")},
	}
	inventory, err := DiscoverDependencyInventory(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Dependencies) != 7 {
		t.Fatalf("parsed %d exact dependencies, want 7: %#v", len(inventory.Dependencies), inventory.Dependencies)
	}
	if len(inventory.Unsupported) != 1 || !strings.Contains(strings.Join(inventory.Warnings, "\n"), "not the resolved build graph") {
		t.Fatalf("Go resolution limitation not declared: %#v %#v", inventory.Unsupported, inventory.Warnings)
	}
	for _, dependency := range inventory.Dependencies {
		if dependency.Ecosystem == "Go" {
			t.Fatal("go.mod minimum requirement was treated as a resolved version")
		}
	}
}

func TestRequirementsWithUnpinnedOrIncludedEntriesMarkCoverageIncomplete(t *testing.T) {
	inventory, err := DiscoverDependencyInventory([]scanner.File{{
		Path:    "requirements.txt",
		Content: []byte("requests==2.31.0\nflask>=3.0\n-r extras.txt\n"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Dependencies) != 1 || !strings.Contains(strings.Join(inventory.Warnings, "\n"), "não foram totalmente incluídos") {
		t.Fatalf("unresolved requirements were silently treated as complete: %#v", inventory)
	}
}

func TestDependencyFindingsCorrelateKEVByCVEAlias(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	if err := store.MergeAdvisory(ctx, Advisory{
		ID: "CVE-2024-0001", Source: "cisa-kev", Weaknesses: []string{"CWE-89"},
		Signals: []RiskSignal{{Kind: "kev", Value: "known-exploited", Source: "cisa-kev", AsOf: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}
	dependency := Dependency{Ecosystem: "npm", Name: "ghost", Version: "1.0.0", File: "package-lock.json"}
	if err := store.CacheQuery(ctx, dependency, []Advisory{{
		ID: "OSV-2024-0001", Source: "osv", Aliases: []string{"CVE-2024-0001"}, Summary: "OSV advisory",
	}}, "osv", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeCachedDependencies(ctx, store, []scanner.File{{
		Path:    "package-lock.json",
		Content: []byte(`{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/ghost":{"version":"1.0.0"}}}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Findings) != 1 {
		t.Fatalf("got %d dependency findings, want 1", len(analysis.Findings))
	}
	finding := analysis.Findings[0]
	if finding.Priority != "urgent-review" || len(finding.RiskSignals) != 1 || finding.RiskSignals[0].Source != "cisa-kev" {
		t.Fatalf("KEV signal was not correlated across the CVE alias: %#v", finding)
	}
	if len(finding.CWEIDs) != 1 || finding.CWEIDs[0] != "CWE-89" || !strings.Contains(strings.Join(finding.AdvisoryIDs, ","), "CVE-2024-0001") {
		t.Fatalf("related CWE/advisory IDs missing: %#v", finding)
	}
}

func TestWithdrawnCachedAdvisoryIsNotReported(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	dependency := Dependency{Ecosystem: "npm", Name: "ghost", Version: "1.0.0", File: "package-lock.json"}
	if err := store.CacheQuery(ctx, dependency, []Advisory{{
		ID: "OSV-2024-0001", Source: "osv", Summary: "Withdrawn advisory", Withdrawn: "2026-10-01T00:00:00Z",
	}}, "osv", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeCachedDependencies(ctx, store, []scanner.File{{
		Path:    "package-lock.json",
		Content: []byte(`{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/ghost":{"version":"1.0.0"}}}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Findings) != 0 {
		t.Fatalf("withdrawn advisory produced findings: %#v", analysis.Findings)
	}
}

func TestNPMParserRejectsDuplicateKeys(t *testing.T) {
	_, err := parseNPM(scanner.File{Path: "package-lock.json", Content: []byte(`{"lockfileVersion":3,"packages":{},"packages":{}}`)})
	if err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
}

func TestDependencyInventoryRecognizesUnsupportedLockfiles(t *testing.T) {
	inventory, err := DiscoverDependencyInventory([]scanner.File{{Path: "poetry.lock", Content: []byte("[package]\n")}, {Path: "pnpm-lock.yaml", Content: []byte("lockfileVersion: '9.0'\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Unsupported) != 2 || len(inventory.Dependencies) != 0 {
		t.Fatalf("unsupported adapters not reported: %#v", inventory)
	}
}

func FuzzParseNPM(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`))
	f.Add([]byte(`{"lockfileVersion":3,"packages":{},"packages":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > scanner.MaxFileBytes {
			t.Skip()
		}
		_, _ = parseNPM(scanner.File{Path: "package-lock.json", Content: data})
	})
}

func FuzzNormalizeOSV(f *testing.F) {
	f.Add([]byte(`{"id":"GHSA-2222-2222-2222","summary":"issue"}`))
	f.Add([]byte(`{"id":"GHSA-2222-2222-2222","id":"CVE-2024-0001"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			t.Skip()
		}
		_, _ = normalizeOSV(data)
	})
}
