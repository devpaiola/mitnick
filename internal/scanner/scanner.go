package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitnick-security/mitnick/internal/findings"
)

const MaxFileBytes = 2 << 20
const MaxDiscoveredFiles = 50000
const MaxVisitedEntries = 100000
const MaxTotalBytes = 256 << 20
const MaxExcludePatterns = 128
const MaxExcludeDirs = 128
const MaxExcludePatternBytes = 256

type File struct {
	Path    string
	Content []byte
}

type Scanner interface {
	Name() string
	Capabilities() []string
	Scan(context.Context, string, []File) ([]findings.Finding, error)
}

type DiscoveryOptions struct {
	ExcludeDirs  []string
	Exclude      []string
	IncludeNames []string
	MaxFiles     int
	MaxEntries   int
	MaxBytes     int64
}

type DiscoveryResult struct {
	Files    []File
	Paths    []string
	Warnings []string
	Skipped  int
}

func Discover(root string, opts DiscoveryOptions) (DiscoveryResult, error) {
	return DiscoverContext(context.Background(), root, opts)
}

func DiscoverContext(ctx context.Context, root string, opts DiscoveryOptions) (DiscoveryResult, error) {
	if err := ctx.Err(); err != nil {
		return DiscoveryResult{}, err
	}
	if err := ValidateExclusions(opts.Exclude, opts.ExcludeDirs); err != nil {
		return DiscoveryResult{}, err
	}
	includeNames := make(map[string]struct{}, len(opts.IncludeNames))
	for _, name := range opts.IncludeNames {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
			return DiscoveryResult{}, fmt.Errorf("nome de arquivo incluído inválido: %q", name)
		}
		includeNames[name] = struct{}{}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return DiscoveryResult{}, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("não foi possível abrir a pasta do scan: %w", err)
	}
	if !info.IsDir() {
		return DiscoveryResult{}, fmt.Errorf("o destino do scan precisa ser uma pasta: %s", root)
	}
	rootReal, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("não foi possível resolver a pasta do scan: %w", err)
	}

	if opts.MaxFiles <= 0 || opts.MaxFiles > MaxDiscoveredFiles {
		opts.MaxFiles = MaxDiscoveredFiles
	}
	if opts.MaxEntries <= 0 || opts.MaxEntries > MaxVisitedEntries {
		opts.MaxEntries = MaxVisitedEntries
	}
	if opts.MaxBytes <= 0 || opts.MaxBytes > MaxTotalBytes {
		opts.MaxBytes = MaxTotalBytes
	}
	ignoredDirs := map[string]bool{".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, ".next": true, "coverage": true, ".mitnick": true}
	for _, name := range opts.ExcludeDirs {
		ignoredDirs[strings.TrimSpace(name)] = true
	}
	result := DiscoveryResult{}
	patterns := append([]string(nil), opts.Exclude...)
	if data, e := readIgnoreFile(rootReal); e != nil {
		result.Warnings = append(result.Warnings, "não foi possível ler .mitnickignore; o arquivo foi ignorado")
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				if len(patterns) >= MaxExcludePatterns {
					return result, fmt.Errorf("limite de padrões de exclusão excedido (%d)", MaxExcludePatterns)
				}
				patterns = append(patterns, line)
			}
		}
	}
	if err := ValidateExclusions(patterns, opts.ExcludeDirs); err != nil {
		return result, err
	}

	var total int64
	var visited int
	var visitedEntries int
	err = filepath.WalkDir(rootReal, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		visitedEntries++
		if visitedEntries > opts.MaxEntries {
			return fmt.Errorf("limite de entradas excedido (%d)", opts.MaxEntries)
		}
		if walkErr != nil {
			rel, _ := filepath.Rel(rootReal, path)
			result.Warnings = append(result.Warnings, fmt.Sprintf("não foi possível inspecionar %s: %v", filepath.ToSlash(rel), walkErr))
			return nil
		}
		if path == rootReal {
			return nil
		}
		rel, e := filepath.Rel(rootReal, path)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			result.Skipped++
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if ignoredDirs[entry.Name()] || matchesAny(rel, patterns) {
				result.Skipped++
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || matchesAny(rel, patterns) {
			result.Skipped++
			return nil
		}
		result.Paths = append(result.Paths, rel)
		if opts.IncludeNames != nil {
			if _, ok := includeNames[entry.Name()]; !ok {
				return nil
			}
		}
		visited++
		if visited > opts.MaxFiles {
			return fmt.Errorf("limite de arquivos excedido (%d)", opts.MaxFiles)
		}
		fileInfo, e := entry.Info()
		if e != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("não foi possível consultar %s: %v", rel, e))
			return nil
		}
		if fileInfo.Size() > MaxFileBytes {
			result.Skipped++
			result.Warnings = append(result.Warnings, fmt.Sprintf("arquivo acima do limite de %d bytes ignorado: %s", MaxFileBytes, rel))
			return nil
		}
		total += fileInfo.Size()
		if total > opts.MaxBytes {
			return fmt.Errorf("limite total de leitura excedido (%d bytes)", opts.MaxBytes)
		}
		full := filepath.Join(rootReal, filepath.FromSlash(rel))
		resolved, e := filepath.EvalSymlinks(full)
		if e != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("não foi possível resolver o caminho %s", rel))
			return nil
		}
		resolved, e = filepath.Abs(resolved)
		if e != nil {
			return e
		}
		relReal, e := filepath.Rel(rootReal, resolved)
		if e != nil || relReal == ".." || strings.HasPrefix(relReal, ".."+string(filepath.Separator)) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("caminho fora da pasta do scan ignorado: %s", rel))
			result.Skipped++
			return nil
		}
		opened, e := os.Open(resolved)
		if e != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("não foi possível ler %s: %v", rel, e))
			return nil
		}
		openedInfo, e := opened.Stat()
		if e != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(fileInfo, openedInfo) {
			_ = opened.Close()
			result.Warnings = append(result.Warnings, fmt.Sprintf("arquivo mudou durante a descoberta; ignorado: %s", rel))
			result.Skipped++
			return nil
		}
		content, e := io.ReadAll(io.LimitReader(opened, MaxFileBytes+1))
		_ = opened.Close()
		if e != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("não foi possível ler %s: %v", rel, e))
			return nil
		}
		if len(content) > MaxFileBytes {
			result.Skipped++
			return nil
		}
		total += int64(len(content)) - fileInfo.Size()
		if total > opts.MaxBytes {
			return fmt.Errorf("limite total de leitura excedido (%d bytes)", opts.MaxBytes)
		}
		if strings.IndexByte(string(content), 0) >= 0 {
			result.Skipped++
			return nil
		}
		result.Files = append(result.Files, File{Path: rel, Content: content})
		return nil
	})
	if err != nil {
		return result, err
	}
	return result, nil
}

func ValidateExclusions(patterns, dirs []string) error {
	if len(patterns) > MaxExcludePatterns {
		return fmt.Errorf("há mais de %d padrões de exclusão", MaxExcludePatterns)
	}
	if len(dirs) > MaxExcludeDirs {
		return fmt.Errorf("há mais de %d diretórios de exclusão", MaxExcludeDirs)
	}
	for _, raw := range patterns {
		pattern := strings.Trim(strings.TrimSpace(raw), "/")
		if pattern == "" {
			continue
		}
		if len(pattern) > MaxExcludePatternBytes || strings.Contains(pattern, "\\") {
			return fmt.Errorf("padrão de exclusão excede %d bytes ou contém separador não portátil", MaxExcludePatternBytes)
		}
		for _, part := range strings.Split(pattern, "/") {
			if part == "" || part == ".." {
				return fmt.Errorf("padrão de exclusão contém componente inválido")
			}
			if part != "**" {
				if _, err := filepath.Match(part, ""); err != nil {
					return fmt.Errorf("padrão de exclusão inválido: %w", err)
				}
			}
		}
	}
	for _, raw := range dirs {
		name := strings.TrimSpace(raw)
		if name == "" || name == "." || name == ".." || len(name) > 255 || strings.ContainsAny(name, "/\\") {
			return fmt.Errorf("nome de diretório de exclusão inválido")
		}
	}
	return nil
}

func readIgnoreFile(root string) ([]byte, error) {
	name := filepath.Join(root, ".mitnickignore")
	info, err := os.Lstat(name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxFileBytes {
		return nil, fmt.Errorf(".mitnickignore is not a regular file within the size limit")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf(".mitnickignore changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf(".mitnickignore is above the size limit")
	}
	return data, nil
}

func matchesAny(path string, patterns []string) bool {
	target := strings.Split(filepath.ToSlash(path), "/")
	base := filepath.Base(path)
	for _, raw := range patterns {
		p := strings.Trim(strings.TrimSpace(raw), "/")
		if p == "" {
			continue
		}
		parts := strings.Split(filepath.ToSlash(p), "/")
		if globParts(parts, target) {
			return true
		}
		if !strings.Contains(p, "/") && globParts(parts, []string{base}) {
			return true
		}
		if strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func globPath(pattern, target string) bool {
	return globParts(strings.Split(filepath.ToSlash(pattern), "/"), strings.Split(filepath.ToSlash(target), "/"))
}

func globParts(patternParts, targetParts []string) bool {
	previous := make([]bool, len(targetParts)+1)
	previous[0] = true
	for _, part := range patternParts {
		current := make([]bool, len(targetParts)+1)
		if part == "**" {
			current[0] = previous[0]
			for targetIndex := 1; targetIndex <= len(targetParts); targetIndex++ {
				current[targetIndex] = previous[targetIndex] || current[targetIndex-1]
			}
			previous = current
			continue
		}
		for targetIndex := 1; targetIndex <= len(targetParts); targetIndex++ {
			matches, err := filepath.Match(part, targetParts[targetIndex-1])
			current[targetIndex] = err == nil && matches && previous[targetIndex-1]
		}
		previous = current
	}
	return previous[len(targetParts)]
}
