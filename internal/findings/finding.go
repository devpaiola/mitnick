package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "1.0"

type Finding struct {
	ID                string       `json:"id"`
	RuleID            string       `json:"rule_id"`
	Kind              string       `json:"kind,omitempty"`
	Title             string       `json:"title"`
	Description       string       `json:"description"`
	Domain            string       `json:"domain"`
	Severity          string       `json:"severity"`
	Confidence        string       `json:"confidence"`
	State             string       `json:"state"`
	Location          Location     `json:"location"`
	Evidence          string       `json:"evidence"`
	Origin            string       `json:"origin"`
	Recommendation    string       `json:"recommendation"`
	Fingerprint       string       `json:"fingerprint"`
	ObservedAt        time.Time    `json:"observed_at"`
	References        []string     `json:"references,omitempty"`
	CWEIDs            []string     `json:"cwe,omitempty"`
	OWASPIDs          []string     `json:"owasp,omitempty"`
	AdvisoryIDs       []string     `json:"advisories,omitempty"`
	RiskSignals       []RiskSignal `json:"risk_signals,omitempty"`
	Priority          string       `json:"priority,omitempty"`
	PriorityFactors   []string     `json:"priority_factors,omitempty"`
	Detector          *Detector    `json:"detector,omitempty"`
	AssessmentReason  string       `json:"assessment_reason,omitempty"`
	Suppressed        bool         `json:"suppressed,omitempty"`
	SuppressionReason string       `json:"suppression_reason,omitempty"`
}

type RiskSignal struct {
	Kind   string    `json:"kind"`
	Value  string    `json:"value"`
	AsOf   time.Time `json:"as_of,omitempty"`
	Source string    `json:"source"`
}

type Detector struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type Location struct {
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	EndColumn int    `json:"end_column,omitempty"`
}

func New(ruleID, title, description, domain, severity, confidence, state, file string, line int, evidence, origin, recommendation string) Finding {
	key := fmt.Sprintf("%s\x00%s\x00%d\x00%s", ruleID, file, line, evidence)
	sum := sha256.Sum256([]byte(key))
	return Finding{
		ID: "mitnick/" + strings.ToLower(ruleID), RuleID: ruleID, Title: title,
		Description: description, Domain: domain, Severity: severity,
		Confidence: confidence, State: state, Location: Location{File: file, Line: line},
		Evidence: evidence, Origin: origin, Recommendation: recommendation,
		Fingerprint: hex.EncodeToString(sum[:]), ObservedAt: time.Now().UTC(),
	}
}

func Sort(items []Finding) {
	severity := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if severity[strings.ToLower(a.Severity)] != severity[strings.ToLower(b.Severity)] {
			return severity[strings.ToLower(a.Severity)] < severity[strings.ToLower(b.Severity)]
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Fingerprint < b.Fingerprint
	})
}
