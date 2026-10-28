package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteExampleDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mitnick.json")
	if err := WriteExample(path); err != nil {
		t.Fatal(err)
	}
	if err := WriteExample(path); err == nil {
		t.Fatal("existing configuration was overwritten")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mitnick.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"workres":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("unknown configuration key was accepted")
	}
}

func TestLoadRequiresVersionedJSONObject(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `{"workers":4}`, `{"version":0}`} {
		t.Run(input, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mitnick.json")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Load(path); err == nil {
				t.Fatalf("accepted invalid configuration %s", input)
			}
		})
	}
}

func TestDecodeRejectsDuplicateKeysAtEveryObjectLevel(t *testing.T) {
	for _, input := range []string{
		`{"version":1,"version":1}`,
		`{"version":1,"ai":{"provider":"codex","provider":"claude"}}`,
	} {
		if _, err := decode([]byte(input)); err == nil || !strings.Contains(err.Error(), "chaves duplicadas") {
			t.Errorf("duplicate JSON keys were accepted or reported unclearly: %s (%v)", input, err)
		}
	}
}

func TestProjectConfigCannotSelectAICLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mitnick.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"ai":{"provider":"codex"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("project configuration selected an authenticated CLI")
	}
}

func TestAIProfileIsPrivateAndNeverStoresCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path, err := WriteAIProfile(AIConfig{Provider: "codex"})
	if err != nil {
		t.Fatal(err)
	}
	profile, gotPath, found, err := LoadAIProfile()
	if err != nil || !found || gotPath != path {
		t.Fatalf("profile load = %#v, %q, %t, %v", profile, gotPath, found, err)
	}
	if profile.Provider != "codex" {
		t.Fatalf("unexpected profile: %#v", profile)
	}
	if _, err := WriteAIProfile(AIConfig{Provider: "ollama"}); err == nil {
		t.Fatal("removed HTTP provider was accepted in the user profile")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "api_key") || strings.Contains(string(data), "token") || strings.Contains(string(data), "password") {
		t.Fatalf("credential-like setting was persisted: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("profile permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestAIProfileRejectsUnknownMutableCapabilitiesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path, err := DefaultAIProfilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"ai":{"provider":"codex","allow_file_writes":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadAIProfile(); err == nil {
		t.Fatal("profile with an unknown write capability was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, _, err := LoadAIProfile(); err == nil {
		t.Fatal("profile reader accepted a symlink")
	}
	if _, err := WriteAIProfile(AIConfig{Provider: "codex"}); err == nil {
		t.Fatal("profile writer accepted a symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("symlink target changed: %q (%v)", data, err)
	}
}

func TestLoadBoundsConfigFilesAndRejectsNonRegularInputs(t *testing.T) {
	dir := t.TempDir()
	largePath := filepath.Join(dir, "large.json")
	if err := os.WriteFile(largePath, make([]byte, MaxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(largePath); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized config was not rejected: %v", err)
	}
	if _, _, err := Load(dir); err == nil {
		t.Fatal("directory was accepted as a configuration file")
	}
}

func TestConfigValidationChecksExclusions(t *testing.T) {
	for _, tc := range []Config{
		func() Config { cfg := Defaults(); cfg.Exclude = []string{"src/["}; return cfg }(),
		func() Config { cfg := Defaults(); cfg.ExcludeDirs = []string{"../private"}; return cfg }(),
	} {
		if err := Validate(tc); err == nil {
			t.Fatalf("invalid exclusion configuration was accepted: %#v", tc)
		}
	}
}

func FuzzDecodeConfig(f *testing.F) {
	f.Add(`{"version":1,"workers":4,"timeout_seconds":30,"fail_on":"high"}`)
	f.Add(`{"version":1,"workres":4}`)
	f.Add(`{"version":1} {"version":1}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _ = decode([]byte(input))
	})
}
