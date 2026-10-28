package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUnifiedScanIsPassiveAndStable(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(t.TempDir(), "command-ran")
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(`const value = { dangerouslySetInnerHTML: { __html: input } };`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"mcpServers": map[string]any{"sample": map[string]any{"command": "sh", "args": []string{"-c", "touch " + sentinel}}}}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	one, err := Scan(context.Background(), root, Options{Workers: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Scan(context.Background(), root, Options{Workers: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("declared MCP command was executed")
	}
	var got, want []string
	for _, f := range one.Findings {
		got = append(got, f.RuleID+"/"+f.Fingerprint)
	}
	for _, f := range two.Findings {
		want = append(want, f.RuleID+"/"+f.Fingerprint)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings are not stable:\n%v\n%v", got, want)
	}
	seenCode, seenAgent := false, false
	for _, f := range one.Findings {
		seenCode = seenCode || f.Domain == "code"
		seenAgent = seenAgent || f.Domain == "agent"
	}
	if !seenCode || !seenAgent {
		t.Fatalf("expected unified domains, got %#v", one.Findings)
	}
}

func TestSecureAndVulnerableFixturesExerciseAdvisorySnapshot(t *testing.T) {
	for _, fixture := range []string{"secure", "vulnerable"} {
		t.Run(fixture, func(t *testing.T) {
			root := filepath.Join("..", "..", "testdata", fixture)
			result, err := Scan(context.Background(), root, Options{Workers: 2, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int{}
			for _, item := range result.Findings {
				if strings.HasPrefix(item.RuleID, "GHSA-") {
					got[item.RuleID]++
				}
			}
			if fixture == "secure" {
				if len(got) != 0 {
					t.Fatalf("patched dependency fixture triggered advisories: %#v", got)
				}
				return
			}
			want := map[string]int{
				"GHSA-f23m-r3pf-42rh": 1,
				"GHSA-r5fr-rjxr-66jc": 1,
				"GHSA-42h9-826w-cgv3": 1,
				"GHSA-gcfj-64vw-6mp9": 1,
				"GHSA-3pq3-5fj3-cg6v": 1,
				"GHSA-m8m8-qj5v-23w3": 1,
				"GHSA-r4gj-5m52-g5wh": 1,
				"GHSA-x97p-jq2g-jp4f": 1,
				"GHSA-mcj8-r9mp-w47p": 1,
				"GHSA-4jqv-mc3x-m676": 1,
				"GHSA-fv66-9v8q-g76r": 1,
				"GHSA-wx67-qw84-cm4g": 1,
				"GHSA-xvch-5gv4-984h": 1,
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("vulnerable dependency fixture findings differ:\n got %#v\nwant %#v", got, want)
			}
		})
	}
}

func TestCanceledScanReportsScannerErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("const ok = true;"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Scan(ctx, root, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.EngineErrors) == 0 {
		t.Fatal("canceled scanners were reported as successful")
	}
}

func BenchmarkScanFixtures(b *testing.B) {
	for _, target := range []string{"secure", "vulnerable"} {
		b.Run(target, func(b *testing.B) {
			path := filepath.Join("..", "..", "testdata", target)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Scan(context.Background(), path, Options{Workers: 4, Timeout: time.Minute}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkScanRepository(b *testing.B) {
	path := filepath.Join("..", "..")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Scan(context.Background(), path, Options{Workers: 4, Timeout: time.Minute}); err != nil {
			b.Fatal(err)
		}
	}
}
