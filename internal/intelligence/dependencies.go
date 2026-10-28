package intelligence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

var requirementLine = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([A-Za-z0-9_.+!-]+)\s*(?:#.*)?$`)
var cargoPackage = regexp.MustCompile(`^\s*name\s*=\s*"([^"]+)"\s*$`)
var cargoVersion = regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"\s*$`)
var gemPackage = regexp.MustCompile(`^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$`)

// DiscoverDependencies extracts only explicit, resolved package versions from
// supported lockfiles. It never invokes a package manager or reads the network.
func DiscoverDependencies(files []scanner.File) ([]Dependency, []string, error) {
	inventory, err := DiscoverDependencyInventory(files)
	return inventory.Dependencies, inventory.Warnings, err
}

type DependencyInventory struct {
	Dependencies []Dependency
	Manifests    map[string]string
	Unsupported  []string
	Warnings     []string
}

var supportedManifests = map[string]string{
	"package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
	"requirements.txt": "PyPI", "Cargo.lock": "crates.io",
	"composer.lock": "Packagist", "Gemfile.lock": "RubyGems", "packages.lock.json": "NuGet",
}

var unsupportedManifests = map[string]bool{
	"go.mod": true, "go.sum": true,
	"pnpm-lock.yaml": true, "yarn.lock": true, "poetry.lock": true, "uv.lock": true,
	"Pipfile.lock": true, "pom.xml": true, "gradle.lockfile": true, "Package.resolved": true,
	"Podfile.lock": true, "vcpkg.json": true, "conan.lock": true, "pubspec.lock": true,
}

func SupportedDependencyManifestNames() []string {
	names := make([]string, 0, len(supportedManifests))
	for name := range supportedManifests {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func IsUnsupportedDependencyManifest(name string) bool {
	return unsupportedManifests[name]
}

func DiscoverDependencyInventory(files []scanner.File) (DependencyInventory, error) {
	inventory := DependencyInventory{Manifests: make(map[string]string)}
	var dependencies []Dependency
	for _, file := range files {
		base := path.Base(file.Path)
		if ecosystem, ok := supportedManifests[base]; ok {
			inventory.Manifests[file.Path] = ecosystem
		} else if unsupportedManifests[base] {
			inventory.Unsupported = append(inventory.Unsupported, file.Path)
			if base == "go.mod" {
				inventory.Warnings = append(inventory.Warnings, fmt.Sprintf("Go module versions in %s are requirements, not the resolved build graph; OSV was not queried to avoid treating a minimum version as installed", file.Path))
			} else if base == "go.sum" {
				inventory.Warnings = append(inventory.Warnings, fmt.Sprintf("go.sum entries in %s can include module versions outside the selected build graph; OSV was not queried", file.Path))
			}
		}
		var parsed []Dependency
		var err error
		switch base {
		case "package-lock.json", "npm-shrinkwrap.json":
			parsed, err = parseNPM(file)
		case "requirements.txt":
			parsed, err = parseRequirements(file)
		case "Cargo.lock":
			parsed, err = parseCargoLock(file)
		case "composer.lock":
			parsed, err = parseComposerLock(file)
		case "Gemfile.lock":
			parsed, err = parseGemfileLock(file)
		case "packages.lock.json":
			parsed, err = parseNuGetLock(file)
		}
		if err != nil {
			inventory.Warnings = append(inventory.Warnings, fmt.Sprintf("dependências não interpretadas em %s: %v", file.Path, err))
			continue
		}
		if base == "requirements.txt" && hasUnresolvedRequirements(file.Content) {
			inventory.Warnings = append(inventory.Warnings, fmt.Sprintf("requirements sem versão exata ou com includes em %s não foram totalmente incluídos", file.Path))
		}
		dependencies = append(dependencies, parsed...)
	}
	seen := make(map[string]bool, len(dependencies))
	out := make([]Dependency, 0, len(dependencies))
	for _, dep := range dependencies {
		key := strings.ToLower(dep.Ecosystem + "\x00" + dep.Name + "\x00" + dep.Version + "\x00" + dep.File)
		if !seen[key] {
			seen[key] = true
			out = append(out, dep)
		}
	}
	inventory.Dependencies = out
	return inventory, nil
}

func hasUnresolvedRequirements(data []byte) bool {
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		line = strings.SplitN(line, "--hash=", 2)[0]
		line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		if line == "" {
			continue
		}
		for _, includeOption := range []string{"-r", "--requirement", "-c", "--constraint", "-e", "--editable"} {
			if line == includeOption || strings.HasPrefix(line, includeOption+" ") || strings.HasPrefix(line, includeOption+"=") {
				return true
			}
		}
		if strings.HasPrefix(line, "-") {
			continue
		}
		if len(requirementLine.FindStringSubmatch(line)) != 3 {
			return true
		}
	}
	return false
}

type npmLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	Dependencies map[string]npmLegacy `json:"dependencies"`
}

type npmLegacy struct {
	Version      string               `json:"version"`
	Dependencies map[string]npmLegacy `json:"dependencies"`
}

func parseNPM(file scanner.File) ([]Dependency, error) {
	if len(file.Content) > scanner.MaxFileBytes {
		return nil, fmt.Errorf("lockfile excede %d bytes", scanner.MaxFileBytes)
	}
	if err := rejectDuplicateJSONKeys(file.Content); err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(file.Content, &lock); err != nil {
		return nil, fmt.Errorf("JSON inválido")
	}
	if lock.LockfileVersion != 0 && (lock.LockfileVersion < 1 || lock.LockfileVersion > 3) {
		return nil, fmt.Errorf("lockfileVersion npm não suportada")
	}
	var out []Dependency
	for packagePath, item := range lock.Packages {
		if packagePath == "" || item.Version == "" {
			continue
		}
		name := strings.TrimPrefix(packagePath, "node_modules/")
		if index := strings.LastIndex(name, "/node_modules/"); index >= 0 {
			name = name[index+len("/node_modules/"):]
		}
		if name != "" {
			out = append(out, Dependency{Ecosystem: "npm", Name: name, Version: item.Version, File: file.Path})
		}
	}
	if len(out) == 0 && len(lock.Dependencies) > 0 {
		var walk func(map[string]npmLegacy)
		walk = func(items map[string]npmLegacy) {
			for name, item := range items {
				if item.Version != "" {
					out = append(out, Dependency{Ecosystem: "npm", Name: name, Version: item.Version, File: file.Path})
				}
				walk(item.Dependencies)
			}
		}
		walk(lock.Dependencies)
	}
	if len(out) == 0 && len(lock.Packages) == 0 && len(lock.Dependencies) == 0 {
		return nil, fmt.Errorf("lockfile sem tabela packages/dependencies")
	}
	return out, nil
}

func parseRequirements(file scanner.File) ([]Dependency, error) {
	var out []Dependency
	for lineNo, line := range strings.Split(string(file.Content), "\n") {
		line = strings.SplitN(line, "--hash=", 2)[0]
		line = strings.SplitN(line, ";", 2)[0]
		if strings.HasPrefix(strings.TrimSpace(line), "-") || strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		match := requirementLine.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		out = append(out, Dependency{Ecosystem: "PyPI", Name: normalizePythonName(match[1]), Version: match[2], File: file.Path, Line: lineNo + 1})
	}
	return out, nil
}

func normalizePythonName(name string) string {
	name = strings.ToLower(name)
	return strings.NewReplacer("_", "-", ".", "-").Replace(name)
}

func parseCargoLock(file scanner.File) ([]Dependency, error) {
	var out []Dependency
	name, version := "", ""
	flush := func() {
		if name != "" && version != "" {
			out = append(out, Dependency{Ecosystem: "crates.io", Name: name, Version: version, File: file.Path})
		}
		name, version = "", ""
	}
	for _, line := range strings.Split(string(file.Content), "\n") {
		if strings.TrimSpace(line) == "[[package]]" {
			flush()
			continue
		}
		if match := cargoPackage.FindStringSubmatch(line); len(match) == 2 {
			name = match[1]
		}
		if match := cargoVersion.FindStringSubmatch(line); len(match) == 2 {
			version = match[1]
		}
	}
	flush()
	if len(out) == 0 && len(file.Content) != 0 {
		return nil, fmt.Errorf("nenhuma seção [[package]] com name e version")
	}
	return out, nil
}

func parseComposerLock(file scanner.File) ([]Dependency, error) {
	if err := rejectDuplicateJSONKeys(file.Content); err != nil {
		return nil, err
	}
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		DevPackages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal(file.Content, &lock); err != nil {
		return nil, fmt.Errorf("JSON inválido")
	}
	var out []Dependency
	for _, item := range append(lock.Packages, lock.DevPackages...) {
		if item.Name != "" && item.Version != "" {
			out = append(out, Dependency{Ecosystem: "Packagist", Name: item.Name, Version: strings.TrimPrefix(item.Version, "v"), File: file.Path})
		}
	}
	if len(out) == 0 && !bytes.Contains(file.Content, []byte(`"packages"`)) {
		return nil, fmt.Errorf("campo packages ausente")
	}
	return out, nil
}

func parseGemfileLock(file scanner.File) ([]Dependency, error) {
	var out []Dependency
	for lineNo, line := range strings.Split(string(file.Content), "\n") {
		match := gemPackage.FindStringSubmatch(line)
		if len(match) == 3 {
			out = append(out, Dependency{Ecosystem: "RubyGems", Name: match[1], Version: match[2], File: file.Path, Line: lineNo + 1})
		}
	}
	return out, nil
}

func parseNuGetLock(file scanner.File) ([]Dependency, error) {
	if err := rejectDuplicateJSONKeys(file.Content); err != nil {
		return nil, err
	}
	var lock struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
			Type     string `json:"type"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(file.Content, &lock); err != nil {
		return nil, fmt.Errorf("JSON inválido")
	}
	var out []Dependency
	for _, packages := range lock.Dependencies {
		for name, item := range packages {
			if item.Resolved != "" {
				out = append(out, Dependency{Ecosystem: "NuGet", Name: name, Version: strings.TrimPrefix(item.Resolved, "["), File: file.Path})
			}
		}
	}
	if len(out) == 0 && lock.Dependencies == nil {
		return nil, fmt.Errorf("campo dependencies ausente")
	}
	return out, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	return jsonutil.RejectDuplicateKeys(data)
}
