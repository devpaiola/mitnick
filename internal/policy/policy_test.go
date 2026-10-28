package policy

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mitnick-security/mitnick/internal/findings"
)

func TestThresholdAndJustifiedSuppression(t *testing.T) {
	items := []findings.Finding{findings.New("WEB002", "dynamic eval", "desc", "code", "medium", "medium", "suspected", "app.js", 1, "WEB002 pattern matched", "test", "remove eval")}
	files := map[string][]byte{"app.js": []byte("eval(input); // mitnick:ignore WEB002 -- user-controlled data is escaped")}
	items = ApplySuppressions(items, files)
	if !items[0].Suppressed {
		t.Fatal("finding was not suppressed")
	}
	if items[0].SuppressionReason != "user-controlled data is escaped" {
		t.Fatalf("suppression reason not retained: %q", items[0].SuppressionReason)
	}
	if MeetsThreshold(items[0], "critical") {
		t.Fatal("suppressed finding should not fail policy")
	}
	if len(items) != 2 || items[1].RuleID != "POLICY-SUPPRESSION" {
		t.Fatalf("missing audit finding: %#v", items)
	}
	if items[1].Suppressed || !strings.Contains(items[1].Evidence, "user-controlled data is escaped") {
		t.Fatalf("audit record should remain visible and retain the sanitized reason: %#v", items[1])
	}
}

func TestSuppressionRequiresReason(t *testing.T) {
	items := []findings.Finding{findings.New("WEB002", "dynamic eval", "desc", "code", "medium", "medium", "suspected", "app.js", 1, "evidence", "test", "fix")}
	items = ApplySuppressions(items, map[string][]byte{"app.js": []byte("eval(input); // mitnick:ignore WEB002")})
	if items[0].Suppressed {
		t.Fatal("suppression without reason was accepted")
	}
}

func TestSuppressionRequiresARealCommentAndExactRuleID(t *testing.T) {
	for _, line := range []string{
		`const note = "// mitnick:ignore WEB002 -- fake comment"; eval(input);`,
		`eval(input); // mitnick:ignore WEB002-extra -- unrelated rule`,
		`eval(input); // mitnick:ignore WEB002 reason=not the documented syntax`,
		`eval(input); // mitnick:ignore WEB002 --no delimiter space`,
		`eval(input); // mitnick:ignore WEB002 --- malformed delimiter`,
	} {
		items := []findings.Finding{findings.New("WEB002", "dynamic eval", "desc", "code", "medium", "medium", "suspected", "app.js", 1, "evidence", "test", "fix")}
		items = ApplySuppressions(items, map[string][]byte{"app.js": []byte(line)})
		if items[0].Suppressed || len(items) != 1 {
			t.Errorf("non-comment or malformed suppression was accepted: %q: %#v", line, items)
		}
	}
}

func TestSanitizedSuppressionReasonTruncationPreservesUTF8(t *testing.T) {
	got := sanitizeReason(strings.Repeat("x", 239) + "á" + "tail")
	if !utf8.ValidString(got) || len(got) > 240 {
		t.Fatalf("reason truncation produced invalid or oversized UTF-8: valid=%t bytes=%d", utf8.ValidString(got), len(got))
	}
}

func TestSuppressionMarkersInsideMultilineStringsOrMarkdownCodeAreIgnored(t *testing.T) {
	for _, tc := range []struct {
		file, content string
		line          int
		rule          string
	}{
		{"app.js", "const note = `\n// mitnick:ignore WEB002 -- template text\n`;\n", 2, "WEB002"},
		{"supabase/migrations/1.sql", "select '\n-- mitnick:ignore SUP003 -- string content\n';\n", 2, "SUP003"},
		{"app.py", "note = \"\"\"\n# mitnick:ignore SEC005 -- docstring content\n\"\"\"\n", 2, "SEC005"},
		{"AGENTS.md", "```md\n<!-- mitnick:ignore AGENT001 -- code sample -->\n```\n", 2, "AGENT001"},
		{"AGENTS.md", "`example\n<!-- mitnick:ignore AGENT001 -- inline code -->\n`\n", 2, "AGENT001"},
		{"AGENTS.md", "```\n<!-- mitnick:ignore AGENT001 -- still code -->\n```not-a-close\n<!-- mitnick:ignore AGENT001 -- still code -->\n```\n", 4, "AGENT001"},
	} {
		t.Run(tc.file+"/line", func(t *testing.T) {
			finding := findings.New(tc.rule, "finding", "desc", "code", "high", "medium", "suspected", tc.file, tc.line, "evidence", "test", "fix")
			items := ApplySuppressions([]findings.Finding{finding}, map[string][]byte{tc.file: []byte(tc.content)})
			if len(items) != 1 || items[0].Suppressed {
				t.Fatalf("non-comment marker was accepted: %#v", items)
			}
		})
	}
}

func TestSuppressionRecognizesDocumentedCommentSyntax(t *testing.T) {
	for _, tc := range []struct {
		file, line string
	}{
		{"app.js", `eval(input); // mitnick:ignore WEB002 -- reviewed`},
		{".env", `API_KEY=example # mitnick:ignore SEC005 -- test fixture`},
		{"supabase/migrations/1.sql", `select true; -- mitnick:ignore SUP003 -- intentionally public`},
		{"AGENTS.md", `<!-- mitnick:ignore AGENT001 -- quoted instruction is inert -->`},
		{".cursorrules", `<!-- mitnick:ignore AGENT001 -- documented markdown comment -->`},
	} {
		t.Run(tc.file, func(t *testing.T) {
			items := []findings.Finding{findings.New("WEB002", "dynamic eval", "desc", "code", "medium", "medium", "suspected", tc.file, 1, "evidence", "test", "fix")}
			if tc.file == "AGENTS.md" || tc.file == ".cursorrules" {
				items[0].RuleID = "AGENT001"
			}
			if tc.file == ".env" {
				items[0].RuleID = "SEC005"
			}
			if strings.Contains(tc.file, ".sql") {
				items[0].RuleID = "SUP003"
			}
			items = ApplySuppressions(items, map[string][]byte{tc.file: []byte(tc.line)})
			if !items[0].Suppressed || len(items) != 2 {
				t.Fatalf("suppression comment was not applied and audited: %#v", items)
			}
		})
	}
}

func TestSuppressionCannotHideOrRecursivelySuppressItsAuditFinding(t *testing.T) {
	line := `eval(input); // mitnick:ignore WEB002 -- reviewed; mitnick:ignore POLICY-SUPPRESSION -- hide the audit`
	items := []findings.Finding{findings.New("WEB002", "dynamic eval", "desc", "code", "medium", "medium", "suspected", "app.js", 1, "evidence", "test", "fix")}
	items = ApplySuppressions(items, map[string][]byte{"app.js": []byte(line)})
	if len(items) != 2 || !items[0].Suppressed || items[1].RuleID != "POLICY-SUPPRESSION" || items[1].Suppressed {
		t.Fatalf("audit finding was hidden, recursively generated, or missing: %#v", items)
	}
}

func FuzzApplySuppressions(f *testing.F) {
	f.Add("app.js", `eval(input); // mitnick:ignore WEB002 -- reviewed`, "WEB002")
	f.Add("AGENTS.md", "```\n<!-- marker -->\n```", "AGENT001")
	f.Add(".env", "API_KEY=example # mitnick:ignore SEC005", "SEC005")
	f.Fuzz(func(t *testing.T, file, line, rule string) {
		if len(file)+len(line)+len(rule) > 1<<20 {
			t.Skip()
		}
		item := findings.New(rule, "title", "description", "code", "high", "medium", "suspected", file, 1, "evidence", "test", "fix")
		_ = ApplySuppressions([]findings.Finding{item}, map[string][]byte{file: []byte(line)})
	})
}
