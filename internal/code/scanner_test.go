package code

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mitnick-security/mitnick/internal/scanner"
)

func TestSecretEvidenceIsMaskedAndCommentsAreScanned(t *testing.T) {
	keyValue := strings.Join([]string{"AKIAIOSFODNN7", "EXAMPLE"}, "")
	items, err := (Scanner{}).Scan(context.Background(), ".", []scanner.File{{Path: "config/.env", Content: []byte("# copied credential: " + keyValue)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].RuleID != "SEC001" {
		t.Fatalf("got findings %#v", items)
	}
	if strings.Contains(items[0].Evidence, keyValue) {
		t.Fatal("finding evidence contains the credential")
	}
	if !strings.Contains(items[0].Evidence, "REDACTED") {
		t.Fatalf("evidence was not masked: %q", items[0].Evidence)
	}
}

func TestNpmLockfileAdvisoriesAndPatchedVersion(t *testing.T) {
	for _, tc := range []struct {
		version   string
		wantCount int
	}{{"4.17.22", 2}, {"4.17.23", 2}, {"4.18.0", 0}, {"4.18.1", 0}} {
		lock := `{"lockfileVersion":3,"packages":{"":{"name":"sample"},"node_modules/lodash":{"version":"` + tc.version + `"}}}`
		items, err := scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(lock)})
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != tc.wantCount {
			t.Errorf("version %s: got %d findings, want %d", tc.version, len(items), tc.wantCount)
		}
		for _, item := range items {
			if item.State != "validated" || len(item.References) == 0 {
				t.Errorf("advisory missing provenance: %#v", item)
			}
		}
	}
}

func TestNpmAdvisorySnapshotVersionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		pkg     string
		version string
		want    []string
	}{
		{"axios", "0.31.0", []string{"GHSA-pf86-5x62-jrwf", "GHSA-42h9-826w-cgv3", "GHSA-x97p-jq2g-jp4f"}},
		{"axios", "0.32.0", []string{"GHSA-42h9-826w-cgv3", "GHSA-gcfj-64vw-6mp9", "GHSA-x97p-jq2g-jp4f"}},
		{"axios", "0.33.0", []string{"GHSA-x97p-jq2g-jp4f"}},
		{"axios", "1.17.0", []string{"GHSA-gcfj-64vw-6mp9", "GHSA-42h9-826w-cgv3", "GHSA-3pq3-5fj3-cg6v", "GHSA-m8m8-qj5v-23w3", "GHSA-r4gj-5m52-g5wh", "GHSA-x97p-jq2g-jp4f"}},
		{"axios", "1.20.0", nil},
		{"next", "15.5.26", []string{"GHSA-mcj8-r9mp-w47p", "GHSA-4jqv-mc3x-m676"}},
		{"next", "15.5.27", nil},
		{"next", "16.3.7", []string{"GHSA-mcj8-r9mp-w47p", "GHSA-4jqv-mc3x-m676"}},
		{"next", "16.3.8", nil},
		{"react-server-dom-parcel", "19.0.0", []string{"GHSA-fv66-9v8q-g76r"}},
		{"react-server-dom-parcel", "19.2.1", []string{"GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-turbopack", "19.0.0", []string{"GHSA-fv66-9v8q-g76r", "GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-turbopack", "19.0.8", nil},
		{"react-server-dom-webpack", "19.0.0", []string{"GHSA-fv66-9v8q-g76r", "GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-webpack", "19.0.1", []string{"GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-webpack", "19.0.8", nil},
		{"react-server-dom-webpack", "19.1.1", []string{"GHSA-fv66-9v8q-g76r", "GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-webpack", "19.1.2", []string{"GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-webpack", "19.1.9", nil},
		{"react-server-dom-webpack", "19.2.0", []string{"GHSA-fv66-9v8q-g76r", "GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-webpack", "19.2.1", []string{"GHSA-wx67-qw84-cm4g"}},
		{"react-server-dom-webpack", "19.2.8", nil},
		{"minimist", "0.2.3", []string{"GHSA-xvch-5gv4-984h"}},
		{"minimist", "0.2.4", nil},
		{"minimist", "1.2.5", []string{"GHSA-xvch-5gv4-984h"}},
		{"minimist", "1.2.6", nil},
	} {
		t.Run(tc.pkg+"@"+tc.version, func(t *testing.T) {
			lock := `{"lockfileVersion":3,"packages":{"node_modules/` + tc.pkg + `":{"version":"` + tc.version + `"}}}`
			items, err := scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(lock)})
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(items))
			for _, item := range items {
				got = append(got, item.RuleID)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got advisory IDs %v, want %v", got, tc.want)
			}
			for _, id := range tc.want {
				found := false
				for _, gotID := range got {
					found = found || gotID == id
				}
				if !found {
					t.Errorf("missing advisory %s in %v", id, got)
				}
			}
		})
	}
}

func TestEmbeddedAdvisoryRangesHaveValidSourceAndSemver(t *testing.T) {
	var advisories []advisory
	if err := json.Unmarshal(advisoryData, &advisories); err != nil {
		t.Fatal(err)
	}
	if len(advisories) == 0 {
		t.Fatal("embedded advisory snapshot is empty")
	}
	for i, item := range advisories {
		if item.Ecosystem != "npm" || item.Package == "" || item.ID == "" || !strings.HasPrefix(item.URL, "https://github.com/advisories/") {
			t.Errorf("advisory %d is missing supported package/source metadata: %#v", i, item)
		}
		if !validNPMVersion(item.Introduced) || !validNPMVersion(item.Fixed) || compareVersions(item.Introduced, item.Fixed) >= 0 {
			t.Errorf("advisory %s has invalid affected range [%s, %s): %#v", item.ID, item.Introduced, item.Fixed, item)
		}
	}
}

func TestAdvisoryRecommendationUsesBranchSpecificFix(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"node_modules/react-server-dom-webpack":{"version":"19.0.0"}}}`
	items, err := scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.RuleID != "GHSA-fv66-9v8q-g76r" {
			continue
		}
		if !strings.Contains(item.Recommendation, "19.0.1") || !strings.Contains(item.Recommendation, "fixes de outras linhas") {
			t.Fatalf("recommendation could imply an unsafe cross-branch upgrade: %q", item.Recommendation)
		}
		return
	}
	t.Fatalf("missing React Server Components advisory in %#v", items)
}

func TestLegacyNpmLockfileScansNestedDependencies(t *testing.T) {
	lock := `{"lockfileVersion":1,"dependencies":{"outer":{"version":"1.0.0","dependencies":{"lodash":{"version":"4.17.23"}}}}}`
	items, err := scanLockfile(scanner.File{Path: "npm-shrinkwrap.json", Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].RuleID != "GHSA-f23m-r3pf-42rh" || items[1].RuleID != "GHSA-r5fr-rjxr-66jc" {
		t.Fatalf("got %#v", items)
	}
}

func TestLegacyNpmLockfileFindingsPointToTheMatchingNestedVersion(t *testing.T) {
	lock := `{
  "lockfileVersion": 1,
  "dependencies": {
    "outer-a": {"version": "1.0.0", "dependencies": {"lodash": {"version": "4.17.22"}}},
    "outer-b": {"version": "1.0.0", "dependencies": {"lodash": {"version": "4.17.23"}}}
  }
}`
	items, err := scanLockfile(scanner.File{Path: "npm-shrinkwrap.json", Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	wantLine := map[string]int{"4.17.22": 4, "4.17.23": 5}
	seen := map[string]int{}
	for _, item := range items {
		for version, line := range wantLine {
			if strings.Contains(item.Evidence, "lodash@"+version) {
				if item.Location.Line != line {
					t.Errorf("%s points to line %d, want matching %s package on line %d", item.RuleID, item.Location.Line, version, line)
				}
				seen[version]++
			}
		}
	}
	for version := range wantLine {
		if seen[version] == 0 {
			t.Errorf("no findings found for lodash@%s", version)
		}
	}
}

func TestDependencyFindingUsesPackageLocation(t *testing.T) {
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.23"
    }
  }
}`
	items, err := scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Location.Line != 4 || items[1].Location.Line != 4 {
		t.Fatalf("wrong package location: %#v", items)
	}
}

func TestDependencyFindingUsesExactPackageKeyWhenNamesSharePrefix(t *testing.T) {
	lock := `{
  "lockfileVersion": 3,
  "description": "quoted \"node_modules/next\": fake",
  "packages": {
    "node_modules/next-plugin": {
      "version": "15.5.26"
    },
    "node_modules\u002fnext": {
      "version": "15.5.26"
    }
  }
}`
	items, err := scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("expected next advisory findings")
	}
	for _, item := range items {
		if item.Location.Line != 8 {
			t.Errorf("%s points to line %d, want exact next package key on line 8", item.RuleID, item.Location.Line)
		}
	}
}

func TestSemverComparisonIncludesPrereleaseOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"4.17.23-beta.1", "4.17.23", -1},
		{"4.18.0", "4.18.0-beta.2", 1},
		{"4.17.23-beta.2", "4.17.23-beta.10", -1},
		{"18446744073709551616.0.0", "9999999999999999999.0.0", 1},
		{"1.0.0-alpha.18446744073709551616", "1.0.0-alpha.9999999999999999999", 1},
	} {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func FuzzCompareVersions(f *testing.F) {
	f.Add("1.2.3", "1.2.4")
	f.Add("1.0.0-beta.10", "1.0.0-beta.2")
	f.Add("18446744073709551616.0.0", "1.0.0")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a)+len(b) > 1024 {
			t.Skip()
		}
		_ = compareVersions(a, b)
	})
}

func TestNpmLockfileRejectsMalformedAndUnassessableData(t *testing.T) {
	for _, input := range []string{
		`null`,
		`[]`,
		`{}`,
		`{"lockfileVersion":99,"packages":{}}`,
		`{"lockfileVersion":3,"packages":null}`,
		`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.23"},"node_modules/lodash":{"version":"4.18.0"}}}`,
		`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"not-a-version"}}}`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(input)}); err == nil {
				t.Fatalf("accepted malformed or unassessable lockfile %s", input)
			}
		})
	}
}

func TestNpmPackageNamesRemainCaseSensitive(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"node_modules/Lodash":{"version":"4.17.23"}}}`
	items, err := scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(lock)})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("noncanonical package name matched advisories case-insensitively: %#v", items)
	}
}

func TestNpmLockfileSupportsDeepLegacyDependencyTreesIteratively(t *testing.T) {
	lock := `"dependencies":{"lodash":{"version":"4.17.23"}}`
	for range 256 {
		lock = `"dependencies":{"outer":{"version":"1.0.0",` + lock + `}}`
	}
	input := `{"lockfileVersion":1,` + lock + `}`
	items, err := scanLockfile(scanner.File{Path: "npm-shrinkwrap.json", Content: []byte(input)})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("deep dependency tree returned %d findings, want 2", len(items))
	}
}

func TestMalformedNpmLockfileIsAnEngineError(t *testing.T) {
	_, err := (Scanner{}).Scan(context.Background(), ".", []scanner.File{{Path: "package-lock.json", Content: []byte("{broken")}})
	if err == nil {
		t.Fatal("malformed lockfile was reported as a successful dependency scan")
	}
}

func TestPlaceholdersDoNotTriggerGenericSecretRule(t *testing.T) {
	items := scanSecrets(".env.example", 1, `API_KEY="YOUR_API_KEY_HERE"`)
	if len(items) != 0 {
		t.Fatalf("placeholder triggered findings: %#v", items)
	}
}

func TestSecretContainingTestSubstringStillTriggers(t *testing.T) {
	items := scanSecrets(".env", 1, `API_KEY="contest_secret_value_123"`)
	if len(items) != 1 || items[0].RuleID != "SEC005" {
		t.Fatalf("secret was incorrectly treated as a placeholder: %#v", items)
	}
}

func TestEnvironmentCredentialReferencesDoNotLookLikeLiteralSecrets(t *testing.T) {
	for _, line := range []string{
		"const supabaseSecret = process.env.NEXT_PUBLIC_SUPABASE_SECRET_KEY;",
		"const apiKey = import.meta.env.VITE_API_KEY;",
		`const token = Deno.env.get("SERVICE_AUTH_TOKEN");`,
		`const password = os.Getenv("DATABASE_PASSWORD");`,
	} {
		if items := scanSecrets("src/app.ts", 1, line); len(items) != 0 {
			t.Errorf("environment reference triggered a literal-secret rule: %q: %#v", line, items)
		}
	}
}

func TestCloudSecretAssignmentsAreDetected(t *testing.T) {
	assignment := strings.Join([]string{"AWS_", "SECRET_ACCESS_KEY=long_random_", "access_credential"}, "")
	items := scanSecrets(".env", 1, assignment)
	if len(items) != 1 || items[0].RuleID != "SEC005" {
		t.Fatalf("got %#v", items)
	}
}

func TestSecretRuleMatrixIncludesPositiveAndNegativeCases(t *testing.T) {
	github := "ghp_" + strings.Repeat("a", 24)
	fineGrainedGitHub := "github_pat_" + strings.Repeat("c", 50)
	slack := "xoxb-" + strings.Repeat("b", 24)
	positive := strings.Join([]string{
		"const aws = AKIAIOSFODNN7EXAMPLE",
		"const github = " + github,
		"const fineGrainedGitHub = " + fineGrainedGitHub,
		"const slack = " + slack,
		"-----BEGIN PRIVATE KEY-----",
		`API_KEY="long_random_test_credential_value"`,
	}, "\n")
	items := scanSecrets("src/.env", 1, positive)
	seen := map[string]bool{}
	for _, item := range items {
		seen[item.RuleID] = true
		if strings.Contains(item.Evidence, github) || strings.Contains(item.Evidence, fineGrainedGitHub) || strings.Contains(item.Evidence, slack) || strings.Contains(item.Evidence, "long_random_test_credential_value") {
			t.Fatalf("secret value leaked into evidence: %#v", item)
		}
	}
	for _, id := range []string{"SEC001", "SEC002", "SEC003", "SEC004", "SEC005"} {
		if !seen[id] {
			t.Errorf("positive fixture did not trigger %s: %#v", id, items)
		}
	}
	if got := scanSecrets("src/.env.example", 1, `API_KEY="your_api_key_here"`); len(got) != 0 {
		t.Fatalf("placeholder triggered a secret rule: %#v", got)
	}
}

func TestWebPatternsAreLimitedToJavaScriptAndTypeScript(t *testing.T) {
	items, err := (Scanner{}).Scan(context.Background(), ".", []scanner.File{{Path: "internal/example.go", Content: []byte("dangerouslySetInnerHTML eval(input)")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if strings.HasPrefix(item.RuleID, "WEB") {
			t.Fatalf("web rule applied to Go source: %#v", item)
		}
	}
}

func TestWebAndPublicSupabaseRuleMatrixHasPositiveAndNegativeCases(t *testing.T) {
	positive := []scanner.File{{Path: "src/page.tsx", Content: []byte(strings.Join([]string{
		`const html = { dangerouslySetInnerHTML: { __html: input } };`,
		`const value = eval(input);`,
		`const cors = "access-control-allow-origin: *";`,
		`const agent = { rejectUnauthorized: false };`,
		`const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;`,
		`const secret = process.env.NEXT_PUBLIC_SUPABASE_SECRET_KEY;`,
		`const viteSecret = import.meta.env.VITE_SUPABASE_SECRET_KEY;`,
	}, "\n"))}}
	items, err := (Scanner{}).Scan(context.Background(), ".", positive)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, item := range items {
		seen[item.RuleID] = true
	}
	for _, id := range []string{"WEB001", "WEB002", "WEB003", "WEB004", "SUP001"} {
		if !seen[id] {
			t.Errorf("positive fixture did not trigger %s: %#v", id, items)
		}
	}
	negative := []scanner.File{{Path: "src/safe.ts", Content: []byte("const html = escape(input);\nconst response = await fetch(url);\nconst key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;\n")}}
	items, err = (Scanner{}).Scan(context.Background(), ".", negative)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("safe fixture triggered a rule: %#v", items)
	}
}

func TestSupabaseSecretKeyNamesInPublicEnvAreDetectedButPublishableIsAllowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want int
	}{
		{"next-secret", "process.env.NEXT_PUBLIC_SUPABASE_SECRET_KEY", 1},
		{"vite-secret", "import.meta.env.VITE_SUPABASE_SECRET_KEY", 1},
		{"legacy-service-role", "process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", 1},
		{"publishable", "process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", 0},
		{"server-secret", "process.env.SUPABASE_SECRET_KEY", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := scanCodePatterns("src/app.ts", 1, tc.text)
			count := 0
			for _, item := range items {
				if item.RuleID == "SUP001" {
					count++
				}
			}
			if count != tc.want {
				t.Fatalf("SUP001 matches %d times, want %d: %#v", count, tc.want, items)
			}
		})
	}
}

func TestSupabaseRLSAndEdgeFunctionRules(t *testing.T) {
	files := []scanner.File{
		{Path: "supabase/migrations/001_risky.sql", Content: []byte("-- ALTER TABLE public.items DISABLE ROW LEVEL SECURITY;\nALTER TABLE public.items DISABLE ROW LEVEL SECURITY;\nCREATE POLICY open_read ON public.items USING (true);\nCREATE POLICY open_write ON public.items WITH CHECK (true);\n")},
		{Path: "supabase/config.toml", Content: []byte("[functions.legacy]\nverify_jwt = false\n")},
		{Path: "migrations/outside_supabase.sql", Content: []byte("ALTER TABLE public.items DISABLE ROW LEVEL SECURITY;\n")},
	}
	items, err := (Scanner{}).Scan(context.Background(), ".", files)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, item := range items {
		counts[item.RuleID]++
	}
	for id, want := range map[string]int{"SUP002": 1, "SUP003": 2, "SUP004": 1} {
		if counts[id] != want {
			t.Errorf("%s: got %d findings, want %d (%#v)", id, counts[id], want, items)
		}
	}
}

func TestSafeSupabaseConfigurationDoesNotTriggerRLSRules(t *testing.T) {
	files := []scanner.File{
		{Path: "supabase/migrations/001_safe.sql", Content: []byte("ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;\nCREATE POLICY owner_only ON public.items USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);\n")},
		{Path: "supabase/config.toml", Content: []byte("[functions.private]\nverify_jwt = true\n")},
	}
	items, err := (Scanner{}).Scan(context.Background(), ".", files)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if strings.HasPrefix(item.RuleID, "SUP00") {
			t.Fatalf("safe fixture triggered %s: %#v", item.RuleID, item)
		}
	}
}

func FuzzScanLockfile(f *testing.F) {
	f.Add(`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.23"}}}`)
	f.Add(`{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.22"}}}`)
	f.Add("not a lockfile")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > scanner.MaxFileBytes {
			t.Skip()
		}
		_, _ = scanLockfile(scanner.File{Path: "package-lock.json", Content: []byte(input)})
	})
}
