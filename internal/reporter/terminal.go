package reporter

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/mitnick-security/mitnick/internal/core"
)

func WriteTerminal(w io.Writer, result core.Result, aiReviews []AIReview) error {
	var output strings.Builder
	fmt.Fprintf(&output, "Análise Mitnick · %d arquivos · %d achados · %d ignorados\n", result.FilesScanned, len(result.Findings), result.FilesSkipped)
	for _, coverage := range result.Coverage {
		fmt.Fprintf(&output, "Cobertura %s: %s (%d arquivos)", terminalSafe(coverage.Component), terminalSafe(coverage.Status), coverage.Files)
		if len(coverage.Unsupported) > 0 {
			fmt.Fprintf(&output, "; linguagens sem regra específica: %s", terminalSafe(strings.Join(coverage.Unsupported, ", ")))
		}
		output.WriteByte('\n')
	}
	for _, coverage := range result.DependencyCoverage {
		fmt.Fprintf(&output, "SCA %s: %s (%d dependências; %d consultadas; %d sem cache; %d desatualizadas)\n", terminalSafe(coverage.Ecosystem), terminalSafe(coverage.Status), coverage.Dependencies, coverage.Cached, coverage.Uncached, coverage.Stale)
	}
	for _, f := range result.Findings {
		state := map[string]string{"suspected": "suspeito", "validated": "validado", "informational": "informativo"}[f.State]
		if state == "" {
			state = f.State
		}
		if f.Suppressed {
			state += ", suprimido"
		}
		domain := map[string]string{"code": "código", "dependency": "dependência", "agent": "agente", "policy": "política"}[f.Domain]
		if domain == "" {
			domain = f.Domain
		}
		fmt.Fprintf(&output, "\n[%s] %s  %s:%d\n", terminalSafe(strings.ToUpper(f.Severity)), terminalSafe(f.RuleID), terminalSafe(f.Location.File), f.Location.Line)
		fmt.Fprintf(&output, "  %s (%s, %s)\n", terminalSafe(f.Title), terminalSafe(domain), terminalSafe(state))
		if f.SuppressionReason != "" {
			fmt.Fprintf(&output, "  Justificativa da supressão: %s\n", terminalSafe(f.SuppressionReason))
		}
		fmt.Fprintf(&output, "  %s\n", terminalSafe(f.Description))
		if f.Evidence != "" {
			fmt.Fprintf(&output, "  Evidência: %s\n", terminalSafe(f.Evidence))
		}
		fmt.Fprintf(&output, "  Correção: %s\n", terminalSafe(f.Recommendation))
		if f.Detector != nil {
			fmt.Fprintf(&output, "  Detector: %s %s\n", terminalSafe(f.Detector.Name), terminalSafe(f.Detector.Version))
		}
		if f.AssessmentReason != "" {
			fmt.Fprintf(&output, "  Avaliação: %s\n", terminalSafe(f.AssessmentReason))
		}
		if len(f.CWEIDs) > 0 {
			fmt.Fprintf(&output, "  CWE: %s\n", terminalSafe(strings.Join(f.CWEIDs, ", ")))
		}
		if len(f.OWASPIDs) > 0 {
			fmt.Fprintf(&output, "  OWASP: %s\n", terminalSafe(strings.Join(f.OWASPIDs, ", ")))
		}
		if len(f.AdvisoryIDs) > 0 {
			fmt.Fprintf(&output, "  Advisories: %s\n", terminalSafe(strings.Join(f.AdvisoryIDs, ", ")))
		}
		if f.Priority != "" {
			fmt.Fprintf(&output, "  Prioridade: %s (%s)\n", terminalSafe(f.Priority), terminalSafe(strings.Join(f.PriorityFactors, ", ")))
		}
		for _, signal := range f.RiskSignals {
			fmt.Fprintf(&output, "  Sinal %s: %s (%s; %s)\n", terminalSafe(signal.Kind), terminalSafe(signal.Value), terminalSafe(signal.Source), terminalSafe(signal.AsOf.Format("2006-01-02")))
		}
		for _, ref := range f.References {
			fmt.Fprintf(&output, "  Referência: %s\n", terminalSafe(ref))
		}
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(&output, "\nAviso: %s\n", terminalSafe(warning))
	}
	for _, failure := range result.EngineErrors {
		fmt.Fprintf(&output, "\nErro de scanner: %s\n", terminalSafe(failure))
	}
	for _, review := range aiReviews {
		fmt.Fprintf(&output, "\nObservação consultiva da IA · %s · %s (%s; confiança %s):\n%s\n",
			terminalSafe(review.FindingID), terminalSafe(review.Assessment), terminalSafe(review.AnalysisType),
			terminalSafe(review.Confidence), terminalSafeMultiline(review.Summary))
		if len(review.EvidenceRefs) > 0 {
			fmt.Fprintf(&output, "  Evidências: %s\n", terminalSafe(strings.Join(review.EvidenceRefs, ", ")))
		}
		if len(review.CWEIDs) > 0 {
			fmt.Fprintf(&output, "  CWE existentes no finding: %s\n", terminalSafe(strings.Join(review.CWEIDs, ", ")))
		}
		for _, limitation := range review.Limitations {
			fmt.Fprintf(&output, "  Limitação: %s\n", terminalSafeMultiline(limitation))
		}
		for _, ref := range review.References {
			fmt.Fprintf(&output, "  Referência: %s\n", terminalSafe(ref))
		}
	}
	fmt.Fprintf(&output, "\nDuração: %s\n", result.FinishedAt.Sub(result.StartedAt).Round(1e6))
	_, err := io.WriteString(w, output.String())
	return err
}

func terminalSafe(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, value)
}

func terminalSafeMultiline(value string) string {
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, value)
}
