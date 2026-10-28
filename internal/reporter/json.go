package reporter

import (
	"encoding/json"
	"io"

	"github.com/mitnick-security/mitnick/internal/core"
)

type JSONReport struct {
	core.Result
	AIReviews []AIReview  `json:"ai_reviews,omitempty"`
	AI        *AIMetadata `json:"ai,omitempty"`
}

type AIReview struct {
	FindingID          string   `json:"finding_id"`
	FindingFingerprint string   `json:"finding_fingerprint"`
	AnalysisType       string   `json:"analysis_type"`
	Assessment         string   `json:"assessment"`
	Summary            string   `json:"summary"`
	EvidenceRefs       []string `json:"evidence_refs,omitempty"`
	CWEIDs             []string `json:"cwe_ids,omitempty"`
	Confidence         string   `json:"confidence"`
	Limitations        []string `json:"limitations,omitempty"`
	References         []string `json:"references,omitempty"`
}

type AIMetadata struct {
	Enabled       bool   `json:"enabled"`
	Provider      string `json:"provider"`
	PromptVersion string `json:"prompt_version"`
	Consent       bool   `json:"content_consent"`
}

func WriteJSON(w io.Writer, report JSONReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)
	return enc.Encode(report)
}
