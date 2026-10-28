package intelligence

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

const defaultCacheFreshness = 30 * 24 * time.Hour

type DependencyCoverage struct {
	Ecosystem     string    `json:"ecosystem"`
	Status        string    `json:"status"`
	ManifestFiles []string  `json:"manifest_files,omitempty"`
	Dependencies  int       `json:"dependencies"`
	Cached        int       `json:"cached"`
	Uncached      int       `json:"uncached"`
	Failed        int       `json:"failed"`
	Stale         int       `json:"stale"`
	OldestQuery   time.Time `json:"oldest_query,omitempty"`
	NewestQuery   time.Time `json:"newest_query,omitempty"`
}

type DependencyAnalysis struct {
	Findings []findings.Finding
	Coverage []DependencyCoverage
	Warnings []string
}

func AnalyzeCachedDependencies(ctx context.Context, store *Store, files []scanner.File) (DependencyAnalysis, error) {
	analysis := DependencyAnalysis{}
	inventory, err := DiscoverDependencyInventory(files)
	if err != nil {
		return analysis, err
	}
	coverageByEcosystem := make(map[string]*DependencyCoverage)
	for manifest, ecosystem := range inventory.Manifests {
		item := coverageByEcosystem[ecosystem]
		if item == nil {
			item = &DependencyCoverage{Ecosystem: ecosystem, Status: "complete"}
			coverageByEcosystem[ecosystem] = item
		}
		item.ManifestFiles = append(item.ManifestFiles, manifest)
	}
	for _, dep := range inventory.Dependencies {
		item := coverageByEcosystem[dep.Ecosystem]
		if item == nil {
			item = &DependencyCoverage{Ecosystem: dep.Ecosystem, Status: "complete"}
			coverageByEcosystem[dep.Ecosystem] = item
		}
		item.Dependencies++
		advisories, state, found, err := store.CachedAdvisories(ctx, dep)
		if err != nil {
			item.Failed++
			item.Status = "partial"
			analysis.Warnings = append(analysis.Warnings, fmt.Sprintf("catálogo local não pôde consultar %s %s@%s: %v", dep.Ecosystem, dep.Name, dep.Version, err))
			continue
		}
		if !found {
			item.Uncached++
			if item.Status == "complete" {
				item.Status = "not-cached"
			}
			continue
		}
		if state.Error != "" {
			item.Failed++
			item.Status = "partial"
			analysis.Warnings = append(analysis.Warnings, fmt.Sprintf("última consulta OSV falhou para %s %s@%s; resultados locais anteriores foram preservados: %s", dep.Ecosystem, dep.Name, dep.Version, state.Error))
		}
		item.Cached++
		if item.OldestQuery.IsZero() || state.FetchedAt.Before(item.OldestQuery) {
			item.OldestQuery = state.FetchedAt
		}
		if item.NewestQuery.IsZero() || state.FetchedAt.After(item.NewestQuery) {
			item.NewestQuery = state.FetchedAt
		}
		if time.Since(state.FetchedAt) > defaultCacheFreshness {
			item.Stale++
			if item.Status == "complete" {
				item.Status = "stale"
			}
		}
		for _, advisory := range advisories {
			if advisory.Withdrawn != "" {
				continue
			}
			finding, err := buildDependencyFinding(ctx, store, dep, advisory, state.FetchedAt)
			if err != nil {
				item.Failed++
				item.Status = "partial"
				analysis.Warnings = append(analysis.Warnings, err.Error())
				continue
			}
			analysis.Findings = append(analysis.Findings, finding)
		}
	}
	for _, manifest := range inventory.Unsupported {
		analysis.Warnings = append(analysis.Warnings, fmt.Sprintf("manifesto de dependências reconhecido, mas sem adapter SCA: %s", manifest))
	}
	analysis.Warnings = append(analysis.Warnings, inventory.Warnings...)
	for _, item := range coverageByEcosystem {
		sort.Strings(item.ManifestFiles)
		if item.Uncached > 0 && item.Cached == 0 && item.Status != "partial" {
			item.Status = "not-cached"
		} else if item.Uncached > 0 && item.Cached > 0 && item.Status != "partial" {
			item.Status = "partial"
		}
		analysis.Coverage = append(analysis.Coverage, *item)
	}
	sort.Slice(analysis.Coverage, func(i, j int) bool { return analysis.Coverage[i].Ecosystem < analysis.Coverage[j].Ecosystem })
	sort.Strings(analysis.Warnings)
	findings.Sort(analysis.Findings)
	return analysis, nil
}

func buildDependencyFinding(ctx context.Context, store *Store, dependency Dependency, advisory Advisory, fetchedAt time.Time) (findings.Finding, error) {
	related, err := relatedAdvisories(ctx, store, advisory)
	if err != nil {
		return findings.Finding{}, err
	}
	severity := advisory.Severity
	if severity == "" {
		for _, item := range related {
			if item.Severity != "" {
				severity = item.Severity
				break
			}
		}
	}
	severityKnown := severity != ""
	if severity == "" {
		severity = "info"
	}
	description := advisory.Summary
	if advisory.Details != "" && !strings.Contains(advisory.Details, advisory.Summary) {
		if description != "" {
			description += " "
		}
		description += advisory.Details
	}
	if description == "" {
		description = "O registro de segurança da fonte corresponde a esta versão do pacote."
	}
	description += " O Mitnick não determina reachability, uso em runtime ou condições de exploração."
	if !severityKnown {
		description += " A fonte não forneceu uma gravidade comparável; `info` representa gravidade desconhecida, não ausência de risco."
	}
	recommendation := "Revise a advisory de origem e atualize para uma versão corrigida quando disponível."
	for _, item := range related {
		if fixed := firstFixedVersion(item, dependency.Ecosystem, dependency.Name); fixed != "" {
			recommendation = fmt.Sprintf("Atualize %s para uma versão corrigida indicada pela fonte (a partir de %s) e valide compatibilidade.", dependency.Name, fixed)
			break
		}
	}
	line := dependency.Line
	if line == 0 {
		line = 1
	}
	ruleID := "SCA-OSV-" + strings.ToUpper(strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(advisory.ID))
	evidence := fmt.Sprintf("%s@%s consta na resposta OSV para %s, consultada em %s", dependency.Name, dependency.Version, dependency.Ecosystem, fetchedAt.UTC().Format(time.RFC3339))
	finding := findings.New(ruleID, fmt.Sprintf("Dependência %s em faixa afetada", dependency.Name), description, "dependency", severity, "high", "validated", dependency.File, line, evidence, "osv", recommendation)
	finding.Kind = "dependency-vulnerability"
	finding.Detector = &findings.Detector{Name: "osv-querybatch", Version: "v1"}
	finding.AssessmentReason = "O OSV retornou este registro para o ecossistema, nome e versão exatos do pacote. Isso confirma correspondência com a advisory, mas não comprova reachability ou impacto na implantação."
	for _, item := range related {
		finding.AdvisoryIDs = append(finding.AdvisoryIDs, item.ID)
		finding.AdvisoryIDs = append(finding.AdvisoryIDs, item.Aliases...)
		finding.CWEIDs = append(finding.CWEIDs, item.Weaknesses...)
		finding.References = append(finding.References, item.References...)
		finding.RiskSignals = mergeFindingSignals(finding.RiskSignals, item.Signals)
	}
	finding.AdvisoryIDs = cleanStrings(finding.AdvisoryIDs)
	finding.CWEIDs = cleanStrings(finding.CWEIDs)
	for _, weakness := range finding.CWEIDs {
		categories, err := store.WeaknessCategories(ctx, weakness)
		if err != nil {
			return findings.Finding{}, err
		}
		finding.OWASPIDs = append(finding.OWASPIDs, categories...)
	}
	finding.OWASPIDs = cleanStrings(finding.OWASPIDs)
	finding.References = cleanStrings(append(finding.References, "https://osv.dev/vulnerability/"+urlPathEscape(advisory.ID)))
	for _, signal := range finding.RiskSignals {
		if signal.Kind == "kev" {
			finding.Priority = "urgent-review"
			finding.PriorityFactors = append(finding.PriorityFactors, "cisa-kev-known-exploited")
			break
		}
	}
	return finding, nil
}

func relatedAdvisories(ctx context.Context, store *Store, advisory Advisory) ([]Advisory, error) {
	identifiers := append([]string{advisory.ID}, advisory.Aliases...)
	seen := map[string]bool{strings.ToLower(advisory.ID): true}
	out := []Advisory{advisory}
	for _, identifier := range cleanStrings(identifiers) {
		matches, err := store.LookupAll(ctx, identifier)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			key := strings.ToLower(match.ID)
			if !seen[key] {
				seen[key] = true
				out = append(out, match)
			}
		}
	}
	return out, nil
}

func mergeFindingSignals(left []findings.RiskSignal, right []RiskSignal) []findings.RiskSignal {
	merged := make([]RiskSignal, 0, len(left)+len(right))
	for _, signal := range left {
		merged = append(merged, RiskSignal{Kind: signal.Kind, Value: signal.Value, AsOf: signal.AsOf, Source: signal.Source})
	}
	for _, signal := range right {
		merged = append(merged, signal)
	}
	merged = mergeSignals(merged, nil)
	out := make([]findings.RiskSignal, 0, len(merged))
	for _, signal := range merged {
		out = append(out, findings.RiskSignal{Kind: signal.Kind, Value: signal.Value, AsOf: signal.AsOf, Source: signal.Source})
	}
	return out
}

func firstFixedVersion(advisory Advisory, ecosystem, name string) string {
	for _, affected := range advisory.Affected {
		if !strings.EqualFold(affected.Ecosystem, ecosystem) || !strings.EqualFold(affected.Name, name) {
			continue
		}
		if len(affected.FixedVersions) > 0 {
			return affected.FixedVersions[0]
		}
		for _, versionRange := range affected.Ranges {
			for _, event := range versionRange.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

func urlPathEscape(value string) string {
	return url.PathEscape(value)
}
