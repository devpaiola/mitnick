package intelligence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA journal_mode = DELETE;
PRAGMA synchronous = FULL;
CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY,
  version TEXT NOT NULL DEFAULT '',
  last_sync TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  record_count INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sync_runs (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,
  record_count INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS advisories (
  id TEXT PRIMARY KEY COLLATE NOCASE,
  source TEXT NOT NULL,
  document TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS advisory_sources (
  source TEXT NOT NULL,
  source_id TEXT NOT NULL COLLATE NOCASE,
  advisory_id TEXT NOT NULL COLLATE NOCASE REFERENCES advisories(id) ON DELETE CASCADE,
  raw_source BLOB,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source, source_id)
);
CREATE TABLE IF NOT EXISTS aliases (
  alias TEXT NOT NULL COLLATE NOCASE,
  advisory_id TEXT NOT NULL COLLATE NOCASE REFERENCES advisories(id) ON DELETE CASCADE,
  PRIMARY KEY (alias, advisory_id)
);
CREATE INDEX IF NOT EXISTS aliases_advisory_id ON aliases(advisory_id);
CREATE TABLE IF NOT EXISTS affected_packages (
  advisory_id TEXT NOT NULL COLLATE NOCASE REFERENCES advisories(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL COLLATE NOCASE,
  package_name TEXT NOT NULL COLLATE NOCASE,
  document TEXT NOT NULL,
  PRIMARY KEY (advisory_id, ecosystem, package_name, document)
);
CREATE INDEX IF NOT EXISTS affected_package_lookup ON affected_packages(ecosystem, package_name);
CREATE TABLE IF NOT EXISTS signals (
  advisory_id TEXT NOT NULL COLLATE NOCASE REFERENCES advisories(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  as_of TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  PRIMARY KEY (advisory_id, kind, source)
);
CREATE TABLE IF NOT EXISTS package_queries (
  ecosystem TEXT NOT NULL COLLATE NOCASE,
  package_name TEXT NOT NULL COLLATE NOCASE,
  version TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  source TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (ecosystem, package_name, version)
);
CREATE TABLE IF NOT EXISTS package_query_advisories (
  ecosystem TEXT NOT NULL COLLATE NOCASE,
  package_name TEXT NOT NULL COLLATE NOCASE,
  version TEXT NOT NULL,
  advisory_id TEXT NOT NULL COLLATE NOCASE REFERENCES advisories(id) ON DELETE CASCADE,
  PRIMARY KEY (ecosystem, package_name, version, advisory_id),
  FOREIGN KEY (ecosystem, package_name, version)
    REFERENCES package_queries(ecosystem, package_name, version) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS weaknesses (
  id TEXT PRIMARY KEY COLLATE NOCASE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_categories (
  id TEXT PRIMARY KEY COLLATE NOCASE,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  source TEXT NOT NULL,
  url TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS weakness_categories (
  weakness_id TEXT NOT NULL COLLATE NOCASE REFERENCES weaknesses(id) ON DELETE CASCADE,
  category_id TEXT NOT NULL COLLATE NOCASE REFERENCES risk_categories(id) ON DELETE CASCADE,
  provenance TEXT NOT NULL,
  PRIMARY KEY (weakness_id, category_id)
);
CREATE TABLE IF NOT EXISTS detection_rules (
  id TEXT PRIMARY KEY COLLATE NOCASE,
  document TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS examples (
  id TEXT PRIMARY KEY COLLATE NOCASE,
  document TEXT NOT NULL
);
`

const currentSchemaVersion = 1

type Store struct {
	db   *sql.DB
	path string
}

func DefaultPath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("diretório de cache indisponível: %w", err)
	}
	return filepath.Join(dir, "mitnick", "intelligence.sqlite"), nil
}

func OpenDefault() (*Store, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return Open(path)
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("caminho do catálogo vazio")
	}
	if path == ":memory:" {
		return openDatabase(path, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("caminho do catálogo inválido: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("não foi possível criar o diretório do catálogo: %w", err)
	}
	info, err := os.Lstat(abs)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("o catálogo precisa ser um arquivo regular, não um symlink ou dispositivo")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(abs, 0o600); err != nil {
				return nil, fmt.Errorf("não foi possível restringir as permissões do catálogo: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("não foi possível inspecionar o catálogo: %w", err)
	} else {
		file, createErr := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil && !errors.Is(createErr, os.ErrExist) {
			return nil, fmt.Errorf("não foi possível criar o catálogo: %w", createErr)
		}
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				return nil, closeErr
			}
		}
	}
	uriPath := filepath.ToSlash(abs)
	if runtime.GOOS == "windows" && len(uriPath) >= 2 && uriPath[1] == ':' {
		uriPath = "/" + uriPath
	}
	uri := (&url.URL{Scheme: "file", Path: uriPath}).String()
	return openDatabase(uri+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", abs)
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("não foi possível criar o diretório privado do catálogo: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("não foi possível inspecionar o diretório privado do catálogo: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("o diretório privado do catálogo precisa ser um diretório real")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("não foi possível restringir as permissões do diretório privado do catálogo: %w", err)
		}
	}
	return nil
}

func openDatabase(dsn, path string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("não foi possível abrir o catálogo SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("não foi possível conectar ao catálogo SQLite: %w", err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("não foi possível ler a versão do catálogo: %w", err)
	}
	if version > currentSchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("versão de schema %d não é suportada (máxima %d)", version, currentSchemaVersion)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("não foi possível inicializar o catálogo SQLite: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("não foi possível migrar o catálogo: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

func migrateSchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("versão de schema %d não é suportada (máxima %d)", version, currentSchemaVersion)
	}
	if version == currentSchemaVersion {
		return nil
	}
	if err := migrateAliasIndex(db); err != nil {
		return err
	}
	_, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, currentSchemaVersion))
	return err
}

func migrateAliasIndex(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(aliases)`)
	if err != nil {
		return err
	}
	primaryKeys := make(map[string]int)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if primaryKey != 0 {
			primaryKeys[name] = primaryKey
		}
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(primaryKeys) == 2 && primaryKeys["alias"] == 1 && primaryKeys["advisory_id"] == 2 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`ALTER TABLE aliases RENAME TO aliases_legacy`,
		`DROP INDEX IF EXISTS aliases_advisory_id`,
		`CREATE TABLE aliases (alias TEXT NOT NULL COLLATE NOCASE, advisory_id TEXT NOT NULL COLLATE NOCASE REFERENCES advisories(id) ON DELETE CASCADE, PRIMARY KEY(alias, advisory_id))`,
		`INSERT OR IGNORE INTO aliases(alias,advisory_id) SELECT alias,advisory_id FROM aliases_legacy`,
		`DROP TABLE aliases_legacy`,
		`CREATE INDEX aliases_advisory_id ON aliases(advisory_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Path() string { return s.path }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) StartSync(ctx context.Context, source string) (int64, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO sync_runs(source, started_at, state) VALUES (?, ?, 'running')`, source, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) FinishSync(ctx context.Context, runID int64, status SourceStatus, errText string) error {
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	if status.LastSync.IsZero() {
		status.LastSync = time.Now().UTC()
	}
	if errText != "" {
		status.State, status.Error = "error", errText
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `UPDATE sync_runs SET finished_at=?, state=?, record_count=?, error=? WHERE id=?`, finished, status.State, status.RecordCount, status.Error, runID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sources(name,version,last_sync,state,record_count,error) VALUES(?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET version=excluded.version,last_sync=excluded.last_sync,state=excluded.state,record_count=excluded.record_count,error=excluded.error`,
		status.Name, status.Version, status.LastSync.UTC().Format(time.RFC3339Nano), status.State, status.RecordCount, status.Error)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SaveWeakness(ctx context.Context, id, name, description, source, version string) error {
	if id == "" || name == "" || source == "" {
		return errors.New("weakness incompleta")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO weaknesses(id,name,description,source,version,updated_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,source=excluded.source,version=excluded.version,updated_at=excluded.updated_at
		WHERE weaknesses.source='cwe-curated'`,
		id, name, description, source, version, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SaveWeaknesses(ctx context.Context, weaknesses []WeaknessRecord, source, version string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, weakness := range weaknesses {
		if weakness.ID == "" || weakness.Name == "" {
			return errors.New("CWE sem identificador ou nome")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO weaknesses(id,name,description,source,version,updated_at) VALUES(?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,source=excluded.source,version=excluded.version,updated_at=excluded.updated_at`, weakness.ID, weakness.Name, weakness.Description, source, version, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SaveCategory(ctx context.Context, id, name, version, source, url string) error {
	if id == "" || name == "" || version == "" || source == "" {
		return errors.New("risk category incompleta")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO risk_categories(id,name,version,source,url) VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version,source=excluded.source,url=excluded.url`, id, name, version, source, url)
	return err
}

func (s *Store) SaveMapping(ctx context.Context, weaknessID, categoryID, provenance string) error {
	if weaknessID == "" || categoryID == "" || provenance == "" {
		return errors.New("mapeamento precisa indicar CWE, categoria e proveniência")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO weakness_categories(weakness_id,category_id,provenance) VALUES(?,?,?)
		ON CONFLICT(weakness_id,category_id) DO UPDATE SET provenance=excluded.provenance`, weaknessID, categoryID, provenance)
	return err
}

func (s *Store) SaveExample(ctx context.Context, id string, example any) error {
	if id == "" {
		return errors.New("example sem ID")
	}
	document, err := json.Marshal(example)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO examples(id,document) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document`, id, string(document))
	return err
}

func (s *Store) SaveRule(ctx context.Context, id string, rule any) error {
	if id == "" {
		return errors.New("regra sem ID")
	}
	document, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO detection_rules(id,document) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document`, id, string(document))
	return err
}

func (s *Store) SaveSourceState(ctx context.Context, status SourceStatus) error {
	if status.Name == "" || status.State == "" {
		return errors.New("estado de fonte incompleto")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sources(name,version,last_sync,state,record_count,error) VALUES(?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET version=excluded.version,last_sync=CASE WHEN excluded.last_sync='' THEN sources.last_sync ELSE excluded.last_sync END,
		state=excluded.state,record_count=excluded.record_count,error=excluded.error`,
		status.Name, status.Version, timeText(status.LastSync), status.State, status.RecordCount, status.Error)
	return err
}

func (s *Store) PutAdvisories(ctx context.Context, advisories []Advisory) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, advisory := range advisories {
		if err := putAdvisory(ctx, tx, advisory); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MergeAdvisory attaches source evidence to an existing canonical record when
// an incoming identifier is already known as an alias.
func (s *Store) MergeAdvisory(ctx context.Context, incoming Advisory) error {
	canonical, found, err := s.lookupCanonical(ctx, incoming.ID)
	if err != nil {
		return err
	}
	if !found {
		matches := make(map[string]Advisory)
		for _, identifier := range append([]string{incoming.ID}, incoming.Aliases...) {
			advisories, err := s.LookupAll(ctx, identifier)
			if err != nil {
				return err
			}
			for _, advisory := range advisories {
				matches[strings.ToLower(advisory.ID)] = advisory
			}
		}
		if len(matches) == 1 {
			for _, match := range matches {
				canonical, found = match, true
			}
		}
	}
	if !found {
		return s.PutAdvisories(ctx, []Advisory{incoming})
	}
	canonical.Aliases = cleanStrings(append(canonical.Aliases, incoming.ID))
	canonical.Aliases = cleanStrings(append(canonical.Aliases, incoming.Aliases...))
	canonical.Sources = cleanStrings(append(canonical.Sources, incoming.Sources...))
	canonical.Sources = cleanStrings(append(canonical.Sources, incoming.Source))
	canonical.SourceRecords = mergeSourceRecords(canonical.SourceRecords, incoming.SourceRecords)
	if incoming.Source != "" && incoming.ID != "" {
		canonical.SourceRecords = mergeSourceRecords(canonical.SourceRecords, []SourceRecord{{Source: incoming.Source, ID: incoming.ID, Raw: incoming.RawSource, UpdatedAt: incoming.Modified}})
	}
	if canonical.SourceIDs == nil {
		canonical.SourceIDs = make(map[string]string)
	}
	for source, id := range incoming.SourceIDs {
		canonical.SourceIDs[source] = id
	}
	if incoming.Source != "" && incoming.ID != "" {
		canonical.SourceIDs[incoming.Source] = incoming.ID
	}
	if canonical.SourceRaw == nil {
		canonical.SourceRaw = make(map[string][]byte)
	}
	for source, raw := range incoming.SourceRaw {
		canonical.SourceRaw[source] = append([]byte(nil), raw...)
	}
	if incoming.Source != "" && len(incoming.RawSource) != 0 {
		canonical.SourceRaw[incoming.Source] = append([]byte(nil), incoming.RawSource...)
	}
	canonical.References = cleanStrings(append(canonical.References, incoming.References...))
	canonical.Weaknesses = cleanStrings(append(canonical.Weaknesses, incoming.Weaknesses...))
	canonical.Signals = mergeSignals(canonical.Signals, incoming.Signals)
	canonical.Affected = mergeAffected(canonical.Affected, incoming.Affected)
	newer := canonical.Modified.IsZero() || incoming.Modified.After(canonical.Modified)
	if canonical.Summary == "" {
		canonical.Summary = incoming.Summary
	}
	if canonical.Details == "" {
		canonical.Details = incoming.Details
	}
	if canonical.Severity == "" {
		canonical.Severity = incoming.Severity
	}
	if incoming.Withdrawn != "" {
		canonical.Withdrawn = incoming.Withdrawn
	}
	if canonical.Published.IsZero() {
		canonical.Published = incoming.Published
	}
	if newer {
		canonical.Modified = incoming.Modified
	}
	return s.PutAdvisories(ctx, []Advisory{canonical})
}

func mergeSourceRecords(left, right []SourceRecord) []SourceRecord {
	byIdentity := make(map[string]SourceRecord, len(left)+len(right))
	for _, record := range append(append([]SourceRecord(nil), left...), right...) {
		if record.Source == "" || record.ID == "" {
			continue
		}
		key := strings.ToLower(record.Source + "\x00" + record.ID)
		previous, exists := byIdentity[key]
		if !exists || record.UpdatedAt.After(previous.UpdatedAt) || len(previous.Raw) == 0 {
			if len(record.Raw) == 0 && exists {
				record.Raw = previous.Raw
			}
			byIdentity[key] = record
		}
	}
	out := make([]SourceRecord, 0, len(byIdentity))
	for _, record := range byIdentity {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if !strings.EqualFold(out[i].Source, out[j].Source) {
			return strings.ToLower(out[i].Source) < strings.ToLower(out[j].Source)
		}
		return strings.ToLower(out[i].ID) < strings.ToLower(out[j].ID)
	})
	return out
}

func (s *Store) lookupCanonical(ctx context.Context, identifier string) (Advisory, bool, error) {
	var document string
	err := s.db.QueryRowContext(ctx, `SELECT document FROM advisories WHERE lower(id)=lower(?)`, identifier).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return Advisory{}, false, nil
	}
	if err != nil {
		return Advisory{}, false, err
	}
	var advisory Advisory
	if err := json.Unmarshal([]byte(document), &advisory); err != nil {
		return Advisory{}, false, fmt.Errorf("advisory armazenada inválida: %w", err)
	}
	if err := s.hydrateAdvisory(ctx, &advisory); err != nil {
		return Advisory{}, false, err
	}
	return advisory, true, nil
}

func mergeSignals(left, right []RiskSignal) []RiskSignal {
	indexes := make(map[string]int, len(left)+len(right))
	out := make([]RiskSignal, 0, len(left)+len(right))
	for _, signal := range append(left, right...) {
		key := strings.ToLower(signal.Kind + "\x00" + signal.Source)
		index, exists := indexes[key]
		if !exists {
			indexes[key] = len(out)
			out = append(out, signal)
			continue
		}
		previous := out[index]
		if signal.AsOf.After(previous.AsOf) || signal.AsOf.Equal(previous.AsOf) || previous.AsOf.IsZero() {
			out[index] = signal
		}
	}
	return out
}

func mergeAffected(left, right []AffectedPackage) []AffectedPackage {
	seen := make(map[string]bool, len(left)+len(right))
	out := make([]AffectedPackage, 0, len(left)+len(right))
	for _, item := range append(left, right...) {
		encoded, _ := json.Marshal(item)
		key := string(encoded)
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

type execContext interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func putAdvisory(ctx context.Context, exec execContext, advisory Advisory) error {
	if strings.TrimSpace(advisory.ID) == "" || strings.TrimSpace(advisory.Source) == "" {
		return errors.New("advisory sem ID ou fonte")
	}
	aliases := make([]string, 0, len(advisory.Aliases))
	for _, alias := range advisory.Aliases {
		if !strings.EqualFold(strings.TrimSpace(alias), advisory.ID) {
			aliases = append(aliases, alias)
		}
	}
	advisory.Aliases = cleanStrings(aliases)
	document, err := json.Marshal(advisory)
	if err != nil {
		return fmt.Errorf("não foi possível normalizar advisory %s: %w", advisory.ID, err)
	}
	_, err = exec.ExecContext(ctx, `INSERT INTO advisories(id,source,document,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET source=excluded.source,document=excluded.document,updated_at=excluded.updated_at`, advisory.ID, advisory.Source, string(document), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if _, err := exec.ExecContext(ctx, `DELETE FROM aliases WHERE advisory_id=?`, advisory.ID); err != nil {
		return err
	}
	if _, err := exec.ExecContext(ctx, `DELETE FROM affected_packages WHERE advisory_id=?`, advisory.ID); err != nil {
		return err
	}
	if _, err := exec.ExecContext(ctx, `DELETE FROM signals WHERE advisory_id=? AND source=?`, advisory.ID, advisory.Source); err != nil {
		return err
	}
	sources := cleanStrings(append(advisory.Sources, advisory.Source))
	for source := range advisory.SourceIDs {
		sources = cleanStrings(append(sources, source))
	}
	for _, record := range advisory.SourceRecords {
		sources = cleanStrings(append(sources, record.Source))
	}
	for _, source := range sources {
		sourceID := advisory.SourceIDs[source]
		if sourceID == "" {
			sourceID = advisory.ID
		}
		records := []SourceRecord{{Source: source, ID: sourceID, Raw: advisory.SourceRaw[source]}}
		for _, record := range advisory.SourceRecords {
			if strings.EqualFold(record.Source, source) {
				records = append(records, record)
			}
		}
		for _, record := range mergeSourceRecords(nil, records) {
			if len(record.Raw) == 0 {
				record.Raw = advisory.SourceRaw[source]
			}
			if source == advisory.Source && len(record.Raw) == 0 && len(advisory.RawSource) != 0 && strings.EqualFold(record.ID, advisory.ID) {
				record.Raw = advisory.RawSource
			}
			updatedAt := record.UpdatedAt
			if updatedAt.IsZero() {
				updatedAt = time.Now().UTC()
			}
			if _, err := exec.ExecContext(ctx, `INSERT INTO advisory_sources(source,source_id,advisory_id,raw_source,updated_at) VALUES(?,?,?,?,?)
				ON CONFLICT(source,source_id) DO UPDATE SET advisory_id=excluded.advisory_id,raw_source=COALESCE(excluded.raw_source,advisory_sources.raw_source),updated_at=excluded.updated_at`, source, record.ID, advisory.ID, nullableBytes(record.Raw), updatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
				return err
			}
		}
	}
	for _, alias := range advisory.Aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" || strings.EqualFold(alias, advisory.ID) {
			continue
		}
		if _, err := exec.ExecContext(ctx, `INSERT OR IGNORE INTO aliases(alias,advisory_id) VALUES(?,?)`, alias, advisory.ID); err != nil {
			return err
		}
	}
	for _, affected := range advisory.Affected {
		if affected.Ecosystem == "" || affected.Name == "" {
			continue
		}
		data, err := json.Marshal(affected)
		if err != nil {
			return err
		}
		if _, err := exec.ExecContext(ctx, `INSERT OR IGNORE INTO affected_packages(advisory_id,ecosystem,package_name,document) VALUES(?,?,?,?)`, advisory.ID, affected.Ecosystem, affected.Name, string(data)); err != nil {
			return err
		}
	}
	for _, signal := range advisory.Signals {
		if signal.Kind == "" || signal.Source == "" {
			continue
		}
		_, err := exec.ExecContext(ctx, `INSERT INTO signals(advisory_id,kind,value,as_of,source) VALUES(?,?,?,?,?)
			ON CONFLICT(advisory_id,kind,source) DO UPDATE SET value=excluded.value,as_of=excluded.as_of`, advisory.ID, signal.Kind, signal.Value, timeText(signal.AsOf), signal.Source)
		if err != nil {
			return err
		}
	}
	return nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func (s *Store) CacheQuery(ctx context.Context, dependency Dependency, advisories []Advisory, source string, fetchedAt time.Time) error {
	if dependency.Ecosystem == "" || dependency.Name == "" || dependency.Version == "" || source == "" {
		return errors.New("consulta de pacote incompleta")
	}
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, advisory := range advisories {
		if err := putAdvisory(ctx, tx, advisory); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO package_queries(ecosystem,package_name,version,fetched_at,source,error) VALUES(?,?,?,?,?,'')
		ON CONFLICT(ecosystem,package_name,version) DO UPDATE SET fetched_at=excluded.fetched_at,source=excluded.source,error=''`,
		dependency.Ecosystem, dependency.Name, dependency.Version, fetchedAt.UTC().Format(time.RFC3339Nano), source)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM package_query_advisories WHERE ecosystem=? AND package_name=? AND version=?`, dependency.Ecosystem, dependency.Name, dependency.Version); err != nil {
		return err
	}
	for _, advisory := range advisories {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO package_query_advisories(ecosystem,package_name,version,advisory_id) VALUES(?,?,?,?)`, dependency.Ecosystem, dependency.Name, dependency.Version, advisory.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CacheQueryError(ctx context.Context, dependency Dependency, source, message string, fetchedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO package_queries(ecosystem,package_name,version,fetched_at,source,error) VALUES(?,?,?,?,?,?)
		ON CONFLICT(ecosystem,package_name,version) DO UPDATE SET error=excluded.error`,
		dependency.Ecosystem, dependency.Name, dependency.Version, fetchedAt.UTC().Format(time.RFC3339Nano), source, message)
	return err
}

func (s *Store) CachedAdvisories(ctx context.Context, dependency Dependency) ([]Advisory, QueryState, bool, error) {
	state := QueryState{Ecosystem: dependency.Ecosystem, Name: dependency.Name, Version: dependency.Version}
	var fetched, source string
	err := s.db.QueryRowContext(ctx, `SELECT fetched_at,source,error FROM package_queries WHERE ecosystem=? AND package_name=? AND version=?`, dependency.Ecosystem, dependency.Name, dependency.Version).Scan(&fetched, &source, &state.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, state, false, nil
	}
	if err != nil {
		return nil, state, false, err
	}
	state.Source = source
	state.FetchedAt, err = time.Parse(time.RFC3339Nano, fetched)
	if err != nil {
		return nil, state, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.document FROM package_query_advisories q JOIN advisories a ON a.id=q.advisory_id WHERE q.ecosystem=? AND q.package_name=? AND q.version=? ORDER BY a.id`, dependency.Ecosystem, dependency.Name, dependency.Version)
	if err != nil {
		return nil, state, true, err
	}
	var out []Advisory
	for rows.Next() {
		var document string
		var advisory Advisory
		if err := rows.Scan(&document); err != nil {
			return nil, state, true, err
		}
		if err := json.Unmarshal([]byte(document), &advisory); err != nil {
			_ = rows.Close()
			return nil, state, true, fmt.Errorf("advisory armazenada inválida: %w", err)
		}
		out = append(out, advisory)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil {
		return nil, state, true, rowsErr
	}
	if closeErr != nil {
		return nil, state, true, closeErr
	}
	for i := range out {
		if err := s.hydrateAdvisory(ctx, &out[i]); err != nil {
			return nil, state, true, err
		}
	}
	return out, state, true, nil
}

func (s *Store) Lookup(ctx context.Context, identifier string) (Advisory, bool, error) {
	advisories, err := s.LookupAll(ctx, identifier)
	if err != nil || len(advisories) == 0 {
		return Advisory{}, false, err
	}
	return advisories[0], true, nil
}

func (s *Store) LookupAll(ctx context.Context, identifier string) ([]Advisory, error) {
	var document string
	rows, err := s.db.QueryContext(ctx, `SELECT a.document FROM advisories a WHERE lower(a.id)=lower(?)
		UNION SELECT a.document FROM advisories a JOIN aliases x ON x.advisory_id=a.id WHERE lower(x.alias)=lower(?) ORDER BY 1`, identifier, identifier)
	if err != nil {
		return nil, err
	}
	var out []Advisory
	for rows.Next() {
		if err := rows.Scan(&document); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var advisory Advisory
		if err := json.Unmarshal([]byte(document), &advisory); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("advisory armazenada inválida: %w", err)
		}
		out = append(out, advisory)
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil {
		return nil, rowsErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	for i := range out {
		if err := s.hydrateAdvisory(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) hydrateAdvisory(ctx context.Context, advisory *Advisory) error {
	rows, err := s.db.QueryContext(ctx, `SELECT alias FROM aliases WHERE advisory_id=? ORDER BY alias`, advisory.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			_ = rows.Close()
			return err
		}
		advisory.Aliases = append(advisory.Aliases, alias)
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	if closeErr != nil {
		return closeErr
	}
	rows, err = s.db.QueryContext(ctx, `SELECT source,source_id,raw_source,updated_at FROM advisory_sources WHERE advisory_id=? ORDER BY source,source_id`, advisory.ID)
	if err != nil {
		return err
	}
	if advisory.SourceIDs == nil {
		advisory.SourceIDs = make(map[string]string)
	}
	if advisory.SourceRaw == nil {
		advisory.SourceRaw = make(map[string][]byte)
	}
	for rows.Next() {
		var source, sourceID, updatedAtText string
		var raw []byte
		if err := rows.Scan(&source, &sourceID, &raw, &updatedAtText); err != nil {
			_ = rows.Close()
			return err
		}
		advisory.Sources = append(advisory.Sources, source)
		if advisory.SourceIDs[source] == "" {
			advisory.SourceIDs[source] = sourceID
		}
		if len(raw) != 0 {
			if len(advisory.SourceRaw[source]) == 0 {
				advisory.SourceRaw[source] = raw
			}
		}
		updatedAt, parseErr := time.Parse(time.RFC3339Nano, updatedAtText)
		if parseErr != nil {
			_ = rows.Close()
			return parseErr
		}
		advisory.SourceRecords = append(advisory.SourceRecords, SourceRecord{Source: source, ID: sourceID, Raw: append([]byte(nil), raw...), UpdatedAt: updatedAt})
		if !strings.EqualFold(sourceID, advisory.ID) {
			advisory.Aliases = append(advisory.Aliases, sourceID)
		}
	}
	rowsErr, closeErr = rows.Err(), rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	if closeErr != nil {
		return closeErr
	}
	rows, err = s.db.QueryContext(ctx, `SELECT kind,value,as_of,source FROM signals WHERE advisory_id=? ORDER BY kind,source`, advisory.ID)
	if err != nil {
		return err
	}
	var signals []RiskSignal
	for rows.Next() {
		var signal RiskSignal
		var asOf string
		if err := rows.Scan(&signal.Kind, &signal.Value, &asOf, &signal.Source); err != nil {
			_ = rows.Close()
			return err
		}
		if asOf != "" {
			signal.AsOf, err = time.Parse(time.RFC3339Nano, asOf)
			if err != nil {
				_ = rows.Close()
				return err
			}
		}
		signals = append(signals, signal)
	}
	rowsErr, closeErr = rows.Err(), rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	if closeErr != nil {
		return closeErr
	}
	advisory.Aliases = cleanStrings(advisory.Aliases)
	advisory.Sources = cleanStrings(advisory.Sources)
	advisory.SourceRecords = mergeSourceRecords(nil, advisory.SourceRecords)
	advisory.Signals = mergeSignals(advisory.Signals, signals)
	return nil
}

func (s *Store) QueryState(ctx context.Context, ecosystem, name, version string) (QueryState, bool, error) {
	state := QueryState{Ecosystem: ecosystem, Name: name, Version: version}
	var fetched string
	err := s.db.QueryRowContext(ctx, `SELECT fetched_at,source,error FROM package_queries WHERE ecosystem=? AND package_name=? AND version=?`, ecosystem, name, version).Scan(&fetched, &state.Source, &state.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	state.FetchedAt, err = time.Parse(time.RFC3339Nano, fetched)
	return state, err == nil, err
}

func (s *Store) Sources(ctx context.Context) ([]SourceStatus, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,version,last_sync,state,record_count,error FROM sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceStatus
	for rows.Next() {
		var status SourceStatus
		var lastSync string
		if err := rows.Scan(&status.Name, &status.Version, &lastSync, &status.State, &status.RecordCount, &status.Error); err != nil {
			return nil, err
		}
		if lastSync != "" {
			status.LastSync, err = time.Parse(time.RFC3339Nano, lastSync)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, status)
	}
	return out, rows.Err()
}

func (s *Store) Weakness(ctx context.Context, id string) (name, description string, found bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT name,description FROM weaknesses WHERE id=?`, id).Scan(&name, &description)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return name, description, true, nil
}

func (s *Store) WeaknessCategories(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT category_id FROM weakness_categories WHERE weakness_id=? ORDER BY category_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			return nil, err
		}
		out = append(out, category)
	}
	return out, rows.Err()
}

func timeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
