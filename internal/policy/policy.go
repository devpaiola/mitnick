package policy

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mitnick-security/mitnick/internal/findings"
)

func MeetsThreshold(f findings.Finding, threshold string) bool {
	if f.Suppressed || strings.EqualFold(threshold, "none") {
		return false
	}
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	limit, ok := rank[strings.ToLower(threshold)]
	if !ok {
		return false
	}
	return rank[strings.ToLower(f.Severity)] <= limit
}

func ApplySuppressions(items []findings.Finding, files map[string][]byte) []findings.Finding {
	originalCount := len(items)
	commentsByFile := make(map[string][]string)
	for i := 0; i < originalCount; i++ {
		f := &items[i]
		if f.RuleID == "POLICY-SUPPRESSION" || f.Suppressed || f.Location.Line < 1 {
			continue
		}
		comments, ok := commentsByFile[f.Location.File]
		if !ok {
			comments = suppressionComments(f.Location.File, files[f.Location.File])
			commentsByFile[f.Location.File] = comments
		}
		if f.Location.Line > len(comments) {
			continue
		}
		line := comments[f.Location.Line-1]
		marker := "mitnick:ignore " + f.RuleID
		reason := ""
		for at := strings.Index(line, marker); at >= 0; at = strings.Index(line, marker) {
			after := line[at+len(marker):]
			if len(after) > 0 && after[0] == ' ' {
				candidate := strings.TrimSpace(after)
				if strings.HasPrefix(candidate, "--") {
					delimiter := strings.TrimPrefix(candidate, "--")
					if strings.HasPrefix(delimiter, " ") {
						reason = strings.TrimSpace(delimiter)
						if reason != "" {
							break
						}
					}
				}
			}
			next := at + len(marker)
			if next >= len(line) {
				break
			}
			line = line[next:]
		}
		if reason == "" {
			continue
		}
		f.Suppressed = true
		f.SuppressionReason = sanitizeReason(reason)
		evidence := "suppression reason recorded for " + f.RuleID + ": " + f.SuppressionReason
		audit := findings.New("POLICY-SUPPRESSION", "Finding suppressed with a reason", "A source comment suppresses a rule and records a reviewable reason.", f.Domain, "info", "high", "informational", f.Location.File, f.Location.Line, evidence, "inline-suppression", "Review this exception periodically and remove it when the risk is resolved.")
		items = append(items, audit)
	}
	return items
}

type commentState struct {
	blockComment bool
	template     bool
	tripleQuote  string
	quote        byte
	htmlComment  bool
	fenceChar    byte
	fenceLength  int
	inlineTicks  int
}

func suppressionComments(file string, content []byte) []string {
	lines := strings.Split(string(content), "\n")
	comments := make([]string, len(lines))
	ext := strings.ToLower(filepath.Ext(file))
	state := commentState{}
	base := strings.ToLower(filepath.Base(file))
	markdown := ext == ".md" || ext == ".mdx" || ext == ".markdown" || base == ".cursorrules" || base == ".windsurfrules" || base == ".clinerules"
	for i, line := range lines {
		if markdown {
			comments[i] = markdownComment(line, &state)
			continue
		}
		comments[i] = sourceComment(ext, line, &state)
	}
	return comments
}

func sourceComment(ext, line string, state *commentState) string {
	var lineMarker string
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".go", ".c", ".h", ".cc", ".cpp", ".java", ".kt", ".rs", ".swift", ".scss":
		lineMarker = "//"
	case ".css":
		lineMarker = ""
	case ".sql":
		lineMarker = "--"
	case ".env", ".yaml", ".yml", ".toml", ".sh", ".bash", ".py", ".rb":
		lineMarker = "#"
	default:
		return ""
	}
	var comment strings.Builder
	for i := 0; i < len(line); {
		if state.quote != 0 {
			end := quotedEnd(line, i, state.quote)
			if end < 0 {
				return comment.String()
			}
			state.quote = 0
			i = end + 1
			continue
		}
		if state.blockComment {
			end := strings.Index(line[i:], "*/")
			if end < 0 {
				comment.WriteString(line[i:])
				return comment.String()
			}
			comment.WriteString(line[i : i+end])
			state.blockComment = false
			i += end + 2
			continue
		}
		if state.template {
			end := quotedEnd(line, i, '`')
			if end < 0 {
				return comment.String()
			}
			state.template = false
			i = end + 1
			continue
		}
		if state.tripleQuote != "" {
			end := strings.Index(line[i:], state.tripleQuote)
			if end < 0 {
				return comment.String()
			}
			i += end + len(state.tripleQuote)
			state.tripleQuote = ""
			continue
		}
		if (ext == ".py" || ext == ".rb") && i+2 < len(line) && (strings.HasPrefix(line[i:], `"""`) || strings.HasPrefix(line[i:], `'''`)) {
			state.tripleQuote = line[i : i+3]
			i += 3
			continue
		}
		if line[i] == '\'' || line[i] == '"' || line[i] == '`' {
			quote := line[i]
			end := quotedEnd(line, i+1, quote)
			if ext == ".sql" && quote != '`' && end < 0 {
				state.quote = quote
				return comment.String()
			}
			if quote == '`' && end < 0 {
				state.template = true
				return comment.String()
			}
			if end < 0 {
				return comment.String()
			}
			i = end + 1
			continue
		}
		if strings.HasPrefix(line[i:], "/*") {
			state.blockComment = true
			i += 2
			comment.WriteByte(' ')
			continue
		}
		if lineMarker != "" && strings.HasPrefix(line[i:], lineMarker) {
			comment.WriteString(line[i+len(lineMarker):])
			return comment.String()
		}
		i++
	}
	return comment.String()
}

func quotedEnd(line string, start int, quote byte) int {
	for i := start; i < len(line); i++ {
		if line[i] == '\\' {
			i++
			continue
		}
		if line[i] == quote {
			return i
		}
	}
	return -1
}

func markdownComment(line string, state *commentState) string {
	if state.fenceChar != 0 {
		if markdownFenceClose(line, state.fenceChar, state.fenceLength) {
			state.fenceChar = 0
			state.fenceLength = 0
		}
		return ""
	}
	if marker, length := markdownFence(line); marker != 0 {
		state.fenceChar = marker
		state.fenceLength = length
		return ""
	}
	var comment strings.Builder
	for i := 0; i < len(line); {
		if state.inlineTicks != 0 {
			if line[i] == '`' {
				length := backtickRun(line, i)
				if length == state.inlineTicks {
					state.inlineTicks = 0
				}
				i += length
				continue
			}
			i++
			continue
		}
		if state.htmlComment {
			end := strings.Index(line[i:], "-->")
			if end < 0 {
				comment.WriteString(line[i:])
				return comment.String()
			}
			comment.WriteString(line[i : i+end])
			state.htmlComment = false
			return comment.String()
		}
		if line[i] == '`' {
			length := backtickRun(line, i)
			state.inlineTicks = length
			i += length
			continue
		}
		if strings.HasPrefix(line[i:], "<!--") {
			state.htmlComment = true
			i += 4
			continue
		}
		i++
	}
	return comment.String()
}

func backtickRun(value string, start int) int {
	length := 1
	for start+length < len(value) && value[start+length] == '`' {
		length++
	}
	return length
}

func markdownFenceClose(line string, marker byte, minimum int) bool {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[0] != marker {
		return false
	}
	length := 0
	for length < len(trimmed) && trimmed[length] == marker {
		length++
	}
	return length >= minimum && strings.TrimSpace(trimmed[length:]) == ""
}

func markdownFence(line string) (byte, int) {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[0] != '`' && trimmed[0] != '~' {
		return 0, 0
	}
	marker := trimmed[0]
	length := 0
	for length < len(trimmed) && trimmed[length] == marker {
		length++
	}
	if length < 3 {
		return 0, 0
	}
	return marker, length
}

var sensitiveReason = []*regexp.Regexp{
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
	regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*["']?[^\s"']{12,}`),
}

func sanitizeReason(reason string) string {
	for _, pattern := range sensitiveReason {
		reason = pattern.ReplaceAllString(reason, "[REDACTED]")
	}
	reason = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, reason)
	if len(reason) > 240 {
		end := 240
		for end > 0 && end < len(reason) && !utf8.RuneStart(reason[end]) {
			end--
		}
		reason = reason[:end]
	}
	return reason
}
