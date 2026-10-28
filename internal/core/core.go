package core

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mitnick-security/mitnick/internal/agents"
	"github.com/mitnick-security/mitnick/internal/code"
	"github.com/mitnick-security/mitnick/internal/findings"
	"github.com/mitnick-security/mitnick/internal/gitleaks"
	"github.com/mitnick-security/mitnick/internal/intelligence"
	"github.com/mitnick-security/mitnick/internal/policy"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

type Options struct {
	Workers          int
	Timeout          time.Duration
	MaxFiles         int
	MaxBytes         int64
	Exclude          []string
	ExcludeDirs      []string
	Gitleaks         bool
	IntelligencePath string
}

type ScannerCoverage struct {
	Component    string   `json:"component"`
	Status       string   `json:"status"`
	Files        int      `json:"files"`
	Capabilities []string `json:"capabilities,omitempty"`
	Languages    []string `json:"languages,omitempty"`
	Unsupported  []string `json:"unsupported,omitempty"`
}

type Result struct {
	SchemaVersion      string                            `json:"schema_version"`
	Target             string                            `json:"target"`
	StartedAt          time.Time                         `json:"started_at"`
	FinishedAt         time.Time                         `json:"finished_at"`
	FilesScanned       int                               `json:"files_scanned"`
	FilesSkipped       int                               `json:"files_skipped"`
	Findings           []findings.Finding                `json:"findings"`
	Warnings           []string                          `json:"warnings,omitempty"`
	EngineErrors       []string                          `json:"engine_errors,omitempty"`
	Coverage           []ScannerCoverage                 `json:"coverage,omitempty"`
	DependencyCoverage []intelligence.DependencyCoverage `json:"dependency_coverage,omitempty"`
	SourceFiles        []scanner.File                    `json:"-"`
}

type scannerResult struct {
	name     string
	findings []findings.Finding
	err      error
}

func Scan(ctx context.Context, target string, opts Options) (Result, error) {
	started := time.Now().UTC()
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.Timeout > time.Hour {
		opts.Timeout = time.Hour
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	root, err := filepath.Abs(target)
	if err != nil {
		return Result{SchemaVersion: findings.SchemaVersion, Target: target, StartedAt: started, FinishedAt: time.Now().UTC(), EngineErrors: []string{"pasta do scan: " + err.Error()}}, nil
	}
	discovered, err := scanner.DiscoverContext(ctx, root, scanner.DiscoveryOptions{Exclude: opts.Exclude, ExcludeDirs: opts.ExcludeDirs, MaxFiles: opts.MaxFiles, MaxBytes: opts.MaxBytes})
	if opts.Workers < 1 {
		opts.Workers = 4
	}
	if opts.Workers > 64 {
		opts.Workers = 64
	}
	allScanners := []scanner.Scanner{code.Scanner{}, agents.Scanner{}}
	if opts.Gitleaks {
		allScanners = append(allScanners, gitleaks.Scanner{})
	}
	results := make(chan scannerResult, len(allScanners))
	semaphore := make(chan struct{}, opts.Workers)
	for _, current := range allScanners {
		current := current
		go func() {
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				results <- scannerResult{name: current.Name(), err: ctx.Err()}
				return
			}
			defer func() { <-semaphore }()
			items, scanErr := current.Scan(ctx, root, discovered.Files)
			results <- scannerResult{name: current.Name(), findings: items, err: scanErr}
		}()
	}

	result := Result{SchemaVersion: findings.SchemaVersion, Target: root, StartedAt: started, FilesScanned: len(discovered.Files), FilesSkipped: discovered.Skipped, Warnings: discovered.Warnings, SourceFiles: discovered.Files}
	result.Coverage = scannerCoverage(discovered.Files)
	if err != nil {
		result.EngineErrors = append(result.EngineErrors, "descoberta de arquivos: "+err.Error())
	}
	for _, warning := range discovered.Warnings {
		result.EngineErrors = append(result.EngineErrors, "descoberta incompleta: "+warning)
	}
	fileBytes := make(map[string][]byte, len(discovered.Files))
	for _, file := range discovered.Files {
		fileBytes[file.Path] = file.Content
	}
	for range allScanners {
		item := <-results
		result.Findings = append(result.Findings, item.findings...)
		if item.err != nil {
			result.EngineErrors = append(result.EngineErrors, fmt.Sprintf("%s scanner: %v", item.name, item.err))
		}
	}
	suppressionsApplied := false
	store, storeErr := openIntelligenceStore(opts.IntelligencePath)
	if storeErr != nil {
		result.DependencyCoverage = []intelligence.DependencyCoverage{{Ecosystem: "all", Status: "unavailable"}}
		result.Warnings = append(result.Warnings, "análise de dependências sem catálogo local: "+storeErr.Error())
	} else {
		if err := intelligence.SeedCurated(ctx, store); err != nil {
			result.Warnings = append(result.Warnings, "mapeamentos CWE/OWASP locais incompletos: "+err.Error())
		}
		analysis, analyzeErr := intelligence.AnalyzeCachedDependencies(ctx, store, discovered.Files)
		if analyzeErr != nil {
			result.Warnings = append(result.Warnings, "análise de dependências incompleta: "+analyzeErr.Error())
			result.DependencyCoverage = append(result.DependencyCoverage, intelligence.DependencyCoverage{Ecosystem: "all", Status: "partial"})
		} else {
			result.Findings = append(result.Findings, analysis.Findings...)
			result.DependencyCoverage = analysis.Coverage
			result.Warnings = append(result.Warnings, analysis.Warnings...)
		}
		result.Findings = policy.ApplySuppressions(result.Findings, fileBytes)
		suppressionsApplied = true
		if err := intelligence.EnrichFindings(ctx, store, result.Findings); err != nil {
			result.Warnings = append(result.Warnings, "metadados de regras incompletos: "+err.Error())
		}
		if err := store.Close(); err != nil {
			result.Warnings = append(result.Warnings, "não foi possível fechar o catálogo local: "+err.Error())
		}
	}
	if !suppressionsApplied {
		result.Findings = policy.ApplySuppressions(result.Findings, fileBytes)
	}
	result.Findings = deduplicate(result.Findings)
	sort.Strings(result.Warnings)
	sort.Strings(result.EngineErrors)
	findings.Sort(result.Findings)
	result.FinishedAt = time.Now().UTC()
	return result, nil
}

func openIntelligenceStore(path string) (*intelligence.Store, error) {
	if path == "" {
		return intelligence.OpenDefault()
	}
	return intelligence.Open(path)
}

func scannerCoverage(files []scanner.File) []ScannerCoverage {
	codeScanner := code.Scanner{}
	agentScanner := agents.Scanner{}
	codeCoverage := ScannerCoverage{Component: "code", Status: "heuristic-static", Files: len(files), Capabilities: codeScanner.Capabilities(), Languages: []string{"JavaScript", "TypeScript", "SQL", "generic text/config patterns"}}
	unsupported := map[string]bool{}
	supportedExtensions := map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".sql": true, ".json": true, ".toml": true, ".yaml": true, ".yml": true, ".md": true, ".env": true, ".txt": true}
	for _, file := range files {
		extension := strings.ToLower(filepath.Ext(file.Path))
		if extension == "" {
			continue
		}
		if !supportedExtensions[extension] && isSourceLanguageExtension(extension) {
			unsupported[extension] = true
		}
	}
	for extension := range unsupported {
		codeCoverage.Unsupported = append(codeCoverage.Unsupported, extension)
	}
	sort.Strings(codeCoverage.Unsupported)
	agentCoverage := ScannerCoverage{Component: "agents", Status: "passive-static", Files: len(files), Capabilities: agentScanner.Capabilities(), Languages: []string{"agent instruction files", "MCP JSON configuration"}}
	return []ScannerCoverage{codeCoverage, agentCoverage}
}

func isSourceLanguageExtension(extension string) bool {
	switch extension {
	case ".py", ".go", ".rs", ".java", ".kt", ".kts", ".cs", ".php", ".rb", ".swift", ".c", ".h", ".cc", ".cpp", ".hpp", ".m", ".mm":
		return true
	default:
		return false
	}
}

func deduplicate(input []findings.Finding) []findings.Finding {
	seen := make(map[string]bool, len(input))
	output := make([]findings.Finding, 0, len(input))
	for _, item := range input {
		key := item.Fingerprint
		if seen[key] {
			continue
		}
		seen[key] = true
		output = append(output, item)
	}
	return output
}
