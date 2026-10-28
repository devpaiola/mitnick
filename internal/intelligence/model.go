package intelligence

import "time"

// Advisory is the normalized subset of a source record that Mitnick uses.
// RawSource is retained so normalization never discards upstream fields.
type Advisory struct {
	ID            string            `json:"id"`
	Source        string            `json:"source"`
	Sources       []string          `json:"sources,omitempty"`
	SourceRecords []SourceRecord    `json:"source_records,omitempty"`
	SourceIDs     map[string]string `json:"source_ids,omitempty"`
	SourceRaw     map[string][]byte `json:"source_raw,omitempty"`
	Aliases       []string          `json:"aliases,omitempty"`
	Summary       string            `json:"summary,omitempty"`
	Details       string            `json:"details,omitempty"`
	Severity      string            `json:"severity,omitempty"`
	Published     time.Time         `json:"published,omitempty"`
	Modified      time.Time         `json:"modified,omitempty"`
	Withdrawn     string            `json:"withdrawn,omitempty"`
	References    []string          `json:"references,omitempty"`
	Weaknesses    []string          `json:"weaknesses,omitempty"`
	Signals       []RiskSignal      `json:"signals,omitempty"`
	Affected      []AffectedPackage `json:"affected,omitempty"`
	RawSource     []byte            `json:"raw_source,omitempty"`
}

type SourceRecord struct {
	Source    string    `json:"source"`
	ID        string    `json:"id"`
	Raw       []byte    `json:"raw,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type AffectedPackage struct {
	Ecosystem     string         `json:"ecosystem"`
	Name          string         `json:"name"`
	PURL          string         `json:"purl,omitempty"`
	Versions      []string       `json:"versions,omitempty"`
	VersionRange  string         `json:"version_range,omitempty"`
	FixedVersions []string       `json:"fixed_versions,omitempty"`
	Ranges        []VersionRange `json:"ranges,omitempty"`
}

type VersionRange struct {
	Type   string       `json:"type,omitempty"`
	Events []RangeEvent `json:"events,omitempty"`
}

type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type RiskSignal struct {
	Kind   string    `json:"kind"`
	Value  string    `json:"value"`
	AsOf   time.Time `json:"as_of,omitempty"`
	Source string    `json:"source"`
}

type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	File      string `json:"file"`
	Line      int    `json:"line,omitempty"`
}

type QueryState struct {
	Ecosystem string
	Name      string
	Version   string
	FetchedAt time.Time
	Source    string
	Error     string
}

type SourceStatus struct {
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	LastSync    time.Time `json:"last_sync,omitempty"`
	State       string    `json:"state"`
	RecordCount int       `json:"record_count"`
	Error       string    `json:"error,omitempty"`
}

type WeaknessRecord struct {
	ID          string
	Name        string
	Description string
}

type SyncRun struct {
	ID          int64
	Source      string
	StartedAt   time.Time
	FinishedAt  time.Time
	State       string
	RecordCount int
	Error       string
}
