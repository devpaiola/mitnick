package intelligence

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	cweURL              = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
	maxCWEArchiveBytes  = 32 << 20
	maxCWEExpandedBytes = 128 << 20
	maxCWERecords       = 10000
)

type CWEConnector struct {
	Client   *http.Client
	Endpoint string
}

type cweXML struct {
	XMLName    xml.Name `xml:"Weakness_Catalog"`
	Version    string   `xml:"Version,attr"`
	Weaknesses []struct {
		ID          string `xml:"ID,attr"`
		Name        string `xml:"Name,attr"`
		Description string `xml:"Description"`
	} `xml:"Weaknesses>Weakness"`
}

func (c CWEConnector) Sync(ctx context.Context, store *Store) error {
	if store == nil {
		return errors.New("catálogo local não configurado")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = cweURL
	}
	runID, err := store.StartSync(ctx, "mitre-cwe")
	if err != nil {
		return err
	}
	data, err := fetchJSON(ctx, client, endpoint, maxCWEArchiveBytes)
	if err != nil {
		status := SourceStatus{Name: "mitre-cwe", Version: "CWE XML", State: "error", LastSync: time.Now().UTC()}
		_ = store.FinishSync(ctx, runID, status, err.Error())
		return err
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return cweImportFailure(ctx, store, runID, "CWE ZIP inválido", err)
	}
	if len(archive.File) == 0 || len(archive.File) > 16 {
		return cweImportFailure(ctx, store, runID, "CWE ZIP fora do limite", errors.New("quantidade de arquivos inválida"))
	}
	var xmlData []byte
	var totalExpanded uint64
	for _, file := range archive.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if filepath.Ext(file.Name) != ".xml" || strings.Contains(file.Name, "..") || filepath.IsAbs(file.Name) {
			continue
		}
		totalExpanded += file.UncompressedSize64
		if file.UncompressedSize64 > maxCWEExpandedBytes || totalExpanded > maxCWEExpandedBytes {
			return cweImportFailure(ctx, store, runID, "CWE XML excede o limite de expansão", errors.New("arquivo maior que 128 MiB"))
		}
		r, err := file.Open()
		if err != nil {
			return cweImportFailure(ctx, store, runID, "não foi possível abrir CWE XML", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(r, int64(maxCWEExpandedBytes)+1))
		closeErr := r.Close()
		if readErr != nil {
			return cweImportFailure(ctx, store, runID, "não foi possível ler CWE XML", readErr)
		}
		if closeErr != nil {
			return cweImportFailure(ctx, store, runID, "não foi possível fechar CWE XML", closeErr)
		}
		if len(data) > maxCWEExpandedBytes {
			return cweImportFailure(ctx, store, runID, "CWE XML excede o limite de expansão", errors.New("arquivo maior que 128 MiB"))
		}
		xmlData = data
		break
	}
	if len(xmlData) == 0 {
		return cweImportFailure(ctx, store, runID, "CWE ZIP sem arquivo XML", errors.New("arquivo XML não encontrado"))
	}
	var catalog cweXML
	decoder := xml.NewDecoder(bytes.NewReader(xmlData))
	decoder.Strict = true
	if err := decoder.Decode(&catalog); err != nil {
		return cweImportFailure(ctx, store, runID, "CWE XML inválido", err)
	}
	if catalog.XMLName.Local != "Weakness_Catalog" || len(catalog.Weaknesses) == 0 || len(catalog.Weaknesses) > maxCWERecords {
		return cweImportFailure(ctx, store, runID, "CWE XML inesperado", errors.New("catálogo sem fraquezas ou excede o limite"))
	}
	weaknesses := make([]WeaknessRecord, 0, len(catalog.Weaknesses))
	seen := make(map[string]bool, len(catalog.Weaknesses))
	for _, item := range catalog.Weaknesses {
		id, err := strconv.Atoi(item.ID)
		if err != nil || id < 1 || strings.TrimSpace(item.Name) == "" {
			return cweImportFailure(ctx, store, runID, "CWE XML contém registro inválido", fmt.Errorf("ID %q", item.ID))
		}
		key := fmt.Sprintf("CWE-%d", id)
		if seen[key] {
			return cweImportFailure(ctx, store, runID, "CWE XML contém duplicatas", fmt.Errorf("ID %s", key))
		}
		seen[key] = true
		weaknesses = append(weaknesses, WeaknessRecord{ID: key, Name: strings.TrimSpace(item.Name), Description: strings.TrimSpace(item.Description)})
	}
	if catalog.Version == "" {
		return cweImportFailure(ctx, store, runID, "CWE XML sem versão", errors.New("atributo Version ausente"))
	}
	if err := store.SaveWeaknesses(ctx, weaknesses, "mitre-cwe", catalog.Version); err != nil {
		return cweImportFailure(ctx, store, runID, "não foi possível importar CWE", err)
	}
	if err := SeedCurated(ctx, store); err != nil {
		return cweImportFailure(ctx, store, runID, "mapeamentos CWE/OWASP locais incompletos", err)
	}
	status := SourceStatus{Name: "mitre-cwe", Version: catalog.Version, State: "ok", RecordCount: len(weaknesses), LastSync: time.Now().UTC()}
	return store.FinishSync(ctx, runID, status, "")
}

func cweImportFailure(ctx context.Context, store *Store, runID int64, label string, cause error) error {
	status := SourceStatus{Name: "mitre-cwe", Version: "CWE XML", State: "error", LastSync: time.Now().UTC()}
	_ = store.FinishSync(ctx, runID, status, cause.Error())
	return fmt.Errorf("%s: %w", label, cause)
}
