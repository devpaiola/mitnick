# RFC-002 — Finding schema v1

**Status:** aceito para v0.1.0-dev. **Data:** 2026-10-25.

O JSON raiz usa `schema_version: "1.0"`. Cada finding registra id/regra, título, descrição, domínio, severidade, confiança, estado, localização, evidência, origem, recomendação, fingerprint SHA-256 e `observed_at` UTC. Referências são opcionais; advisories embutidas usam URL de origem. Evidências de segredo são substituídas antes de entrar no modelo de finding.

Severidades: `critical`, `high`, `medium`, `low`, `info`. Confiança: `high`, `medium`, `low`. Estado: `suspected`, `validated`, `informational`. Para JSON, campos sem valor opcional são omitidos. Mudança incompatível incrementará a versão principal do schema.

Fingerprints usam regra, path relativo, linha e evidência sanitizada. A ordem dos findings é determinística por severidade, arquivo, linha, regra e fingerprint. Timestamp representa a execução e, por isso, varia entre scans.
