package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/mitnick-security/mitnick/internal/jsonutil"
	"github.com/mitnick-security/mitnick/internal/scanner"
)

type Config struct {
	Version        int      `json:"version"`
	Workers        int      `json:"workers"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	FailOn         string   `json:"fail_on"`
	Exclude        []string `json:"exclude,omitempty"`
	ExcludeDirs    []string `json:"exclude_dirs,omitempty"`
}

type AIConfig struct {
	Provider string `json:"provider,omitempty"`
}

type aiProfile struct {
	Version int      `json:"version"`
	AI      AIConfig `json:"ai"`
}

const MaxConfigBytes = 1 << 20

func Defaults() Config { return Config{Version: 1, Workers: 4, TimeoutSeconds: 30, FailOn: "high"} }

func DefaultAIProfilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("diretório de configuração do usuário indisponível: %w", err)
	}
	return filepath.Join(dir, "mitnick", "ai.json"), nil
}

func LoadAIProfile() (AIConfig, string, bool, error) {
	path, err := DefaultAIProfilePath()
	if err != nil {
		return AIConfig{}, "", false, err
	}
	return ReadAIProfile(path)
}

func ReadAIProfile(path string) (AIConfig, string, bool, error) {
	if path == "" {
		return AIConfig{}, "", false, errors.New("caminho do perfil de IA vazio")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return AIConfig{}, path, false, nil
	}
	if err != nil {
		return AIConfig{}, path, false, err
	}
	if !info.Mode().IsRegular() {
		return AIConfig{}, path, false, errors.New("perfil de IA precisa ser arquivo regular, não symlink ou dispositivo")
	}
	data, err := readConfig(path)
	if err != nil {
		return AIConfig{}, path, false, fmt.Errorf("não foi possível ler o perfil de IA: %w", err)
	}
	if err := jsonutil.RejectDuplicateKeys(data); err != nil {
		return AIConfig{}, path, false, err
	}
	var profile aiProfile
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return AIConfig{}, path, false, fmt.Errorf("perfil de IA inválido: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return AIConfig{}, path, false, errors.New("perfil de IA deve conter somente um objeto")
	}
	if profile.Version != 2 {
		return AIConfig{}, path, false, errors.New("versão do perfil de IA não suportada")
	}
	if !validAIProvider(profile.AI.Provider) {
		return AIConfig{}, path, false, errors.New("perfil de IA deve definir um cliente CLI")
	}
	return profile.AI, path, true, nil
}

func WriteAIProfile(profile AIConfig) (string, error) {
	path, err := DefaultAIProfilePath()
	if err != nil {
		return "", err
	}
	if !validAIProvider(profile.Provider) {
		return "", errors.New("ai.provider deve ser codex ou claude para conectar um cliente CLI")
	}
	if err := ensurePrivateConfigDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return "", errors.New("o perfil de IA precisa ser um arquivo regular, não um symlink ou dispositivo")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	data, err := json.MarshalIndent(aiProfile{Version: 2, AI: profile}, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".ai-profile-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", fmt.Errorf("não foi possível salvar o perfil de IA: %w", err)
	}
	return path, nil
}

func validAIProvider(provider string) bool { return provider == "codex" || provider == "claude" }

func ensurePrivateConfigDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("não foi possível criar o diretório privado de configuração: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("o diretório de configuração precisa ser um diretório real")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("não foi possível restringir permissões do diretório: %w", err)
		}
	}
	return nil
}

func Load(explicit string) (Config, string, error) {
	cfg := Defaults()
	filename := explicit
	if filename == "" {
		for _, candidate := range []string{"mitnick.json", ".mitnick.json"} {
			if _, err := os.Stat(candidate); err == nil {
				filename = candidate
				break
			}
		}
	}
	if filename != "" {
		data, err := readConfig(filename)
		if err != nil {
			return cfg, filename, fmt.Errorf("não foi possível ler a configuração: %w", err)
		}
		cfg, err = decode(data)
		if err != nil {
			return cfg, filename, fmt.Errorf("JSON de configuração inválido: %w", err)
		}
	}
	if cfg.Workers == 0 {
		cfg.Workers = 4
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.FailOn == "" {
		cfg.FailOn = "high"
	}
	if value := os.Getenv("MITNICK_FAIL_ON"); value != "" {
		cfg.FailOn = value
	}
	if value := os.Getenv("MITNICK_WORKERS"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return cfg, filename, errors.New("MITNICK_WORKERS deve ser um inteiro")
		}
		cfg.Workers = n
	}
	if value := os.Getenv("MITNICK_TIMEOUT_SECONDS"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return cfg, filename, errors.New("MITNICK_TIMEOUT_SECONDS deve ser um inteiro")
		}
		cfg.TimeoutSeconds = n
	}
	return cfg, filename, Validate(cfg)
}

func decode(data []byte) (Config, error) {
	if err := jsonutil.RejectDuplicateKeys(data); err != nil {
		return Config{}, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return Config{}, err
	}
	if object == nil {
		return Config{}, errors.New("configuração deve ser um objeto JSON")
	}
	version, ok := object["version"]
	if !ok {
		return Config{}, errors.New("campo version obrigatório")
	}
	var versionNumber int
	if err := json.Unmarshal(version, &versionNumber); err != nil || versionNumber < 1 {
		return Config{}, errors.New("version deve ser um inteiro positivo")
	}
	cfg := Defaults()
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Config{}, errors.New("JSON de configuração deve conter somente um objeto")
	}
	return cfg, nil
}

func readConfig(filename string) ([]byte, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("arquivo de configuração precisa ser regular")
	}
	if info.Size() > MaxConfigBytes {
		return nil, errors.New("arquivo de configuração excede o limite de 1 MiB")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, errors.New("arquivo de configuração mudou durante a abertura")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > MaxConfigBytes {
		return nil, errors.New("arquivo de configuração excede o limite de 1 MiB")
	}
	return data, nil
}

func Validate(cfg Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("versão de configuração %d não suportada (versão aceita: 1)", cfg.Version)
	}
	if cfg.Workers < 1 || cfg.Workers > 64 {
		return errors.New("workers deve estar entre 1 e 64")
	}
	if cfg.TimeoutSeconds < 1 || cfg.TimeoutSeconds > 3600 {
		return errors.New("timeout_seconds deve estar entre 1 e 3600")
	}
	if !validThreshold(cfg.FailOn) {
		return fmt.Errorf("fail_on deve ser critical, high, medium, low, info ou none")
	}
	if err := scanner.ValidateExclusions(cfg.Exclude, cfg.ExcludeDirs); err != nil {
		return err
	}
	return nil
}

func WriteExample(destination string) error {
	data, err := json.MarshalIndent(Defaults(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if destination == "" {
		destination = "mitnick.json"
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite %s", destination)
		}
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(destination)
		return err
	}
	return file.Close()
}

func validThreshold(value string) bool {
	switch strings.ToLower(value) {
	case "critical", "high", "medium", "low", "info", "none":
		return true
	default:
		return false
	}
}
