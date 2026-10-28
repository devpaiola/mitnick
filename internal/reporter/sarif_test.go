package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mitnick-security/mitnick/internal/core"
	"github.com/mitnick-security/mitnick/internal/findings"
)

func TestSARIFIncludesLocationFingerprintAndSuppression(t *testing.T) {
	finding := findings.New("WEB002", "Dynamic code", "desc", "code", "medium", "high", "suspected", "src/my app.js", 7, "pattern", "unit-test", "remove eval")
	finding.Suppressed = true
	var output bytes.Buffer
	if err := WriteSARIF(&output, core.Result{Findings: []findings.Finding{finding}}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(output.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	runs := doc["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	result := results[0].(map[string]any)
	if result["ruleId"] != "WEB002" {
		t.Fatalf("missing rule id: %#v", result)
	}
	physical := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if got := physical["artifactLocation"].(map[string]any)["uri"]; got != "src/my%20app.js" {
		t.Fatalf("SARIF path was not URI-encoded: %v", got)
	}
	if _, ok := result["partialFingerprints"]; !ok {
		t.Fatal("missing stable fingerprint")
	}
	if _, ok := result["suppressions"]; !ok {
		t.Fatal("missing suppression metadata")
	}
}

func TestSARIFMarksIncompleteScanAsFailed(t *testing.T) {
	var output bytes.Buffer
	if err := WriteSARIF(&output, core.Result{EngineErrors: []string{"discovery failed"}}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(output.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	invocation := run["invocations"].([]any)[0].(map[string]any)
	if invocation["executionSuccessful"] != false {
		t.Fatal("SARIF reported a failed scan as successful")
	}
}

func TestSARIFURIEncodesUnicodePath(t *testing.T) {
	finding := findings.New("WEB002", "Dynamic code", "desc", "code", "medium", "high", "suspected", "src/ação.ts", 3, "pattern", "unit-test", "remove eval")
	var output bytes.Buffer
	if err := WriteSARIF(&output, core.Result{Findings: []findings.Finding{finding}}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(output.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	runs := doc["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	physical := results[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if got := physical["artifactLocation"].(map[string]any)["uri"]; got != "src/a%C3%A7%C3%A3o.ts" {
		t.Fatalf("Unicode path was not URI-encoded: %v", got)
	}
}
