package reporter

import (
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"sort"

	"github.com/mitnick-security/mitnick/internal/core"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}
type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}
type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func WriteSARIF(w io.Writer, report core.Result) error {
	byRule := map[string]sarifRule{}
	for _, f := range report.Findings {
		byRule[f.RuleID] = sarifRule{ID: f.RuleID, Name: f.RuleID, ShortDescription: sarifMessage{Text: f.Title}}
	}
	rules := make([]sarifRule, 0, len(byRule))
	for _, rule := range byRule {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	results := make([]sarifResult, 0, len(report.Findings))
	for _, f := range report.Findings {
		level := "note"
		switch f.Severity {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		}
		region := (*sarifRegion)(nil)
		if f.Location.Line > 0 {
			region = &sarifRegion{StartLine: f.Location.Line, StartColumn: f.Location.Column}
		}
		result := sarifResult{RuleID: f.RuleID, Level: level, Message: sarifMessage{Text: f.Title + ": " + f.Description}, Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: artifactURI(f.Location.File)}, Region: region}}}, PartialFingerprints: map[string]string{"mitnick/v1": f.Fingerprint}}
		properties := map[string]any{}
		if f.Kind != "" {
			properties["kind"] = f.Kind
		}
		if len(f.CWEIDs) > 0 {
			properties["cwe"] = f.CWEIDs
		}
		if len(f.OWASPIDs) > 0 {
			properties["owasp"] = f.OWASPIDs
		}
		if len(f.AdvisoryIDs) > 0 {
			properties["advisories"] = f.AdvisoryIDs
		}
		if len(f.RiskSignals) > 0 {
			properties["riskSignals"] = f.RiskSignals
		}
		if f.Priority != "" {
			properties["priority"] = f.Priority
			properties["priorityFactors"] = f.PriorityFactors
		}
		if f.Detector != nil {
			properties["detector"] = f.Detector
		}
		if f.AssessmentReason != "" {
			properties["assessmentReason"] = f.AssessmentReason
		}
		if len(properties) > 0 {
			result.Properties = properties
		}
		if f.Suppressed {
			result.Suppressions = []sarifSuppression{{Kind: "inSource", Justification: f.SuppressionReason}}
		}
		results = append(results, result)
	}
	var notifications []sarifNotification
	for _, err := range report.EngineErrors {
		notifications = append(notifications, sarifNotification{Level: "error", Message: sarifMessage{Text: err}})
	}
	for _, warning := range report.Warnings {
		notifications = append(notifications, sarifNotification{Level: "warning", Message: sarifMessage{Text: warning}})
	}
	invocation := sarifInvocation{ExecutionSuccessful: len(report.EngineErrors) == 0, ToolExecutionNotifications: notifications}
	log := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "Mitnick", Rules: rules}}, Results: results, Invocations: []sarifInvocation{invocation}}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func artifactURI(name string) string {
	return (&url.URL{Path: filepath.ToSlash(name)}).EscapedPath()
}
