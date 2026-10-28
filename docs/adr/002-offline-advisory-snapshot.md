# ADR-002 — Scan offline e inteligência local

**Status:** aceita para v0.1.0-dev. **Data:** 2026-10-25.

## Decisão

O scan não consulta feeds ou serviços externos. Há duas bases locais: um snapshot npm pequeno versionado no binário e um catálogo SQLite opcional com dados baixados antes por `mitnick intel update`. Os dados OSV são consultados por versão exata e o scan lê apenas o cache. O inventário do snapshot embutido está em [`advisory-snapshot.md`](../advisory-snapshot.md); os conectores, cache e cobertura estão em [`data-sources.md`](../data-sources.md).

## Motivo

Evitar chamadas de rede implícitas e manter resultado reproduzível. A base embutida e o cache local são incompletos e podem estar desatualizados; não encontrar um finding não atesta ausência de vulnerabilidades.

## Consequências

O relatório declara cache ausente, falha, stale e cobertura de manifestos quando disponíveis. Atualizações exigem revisão de fonte, limites positivos/negativos, changelog e testes. O sincronizador preserva resultados anteriores se uma fonte falhar; a sincronização continua explícita e separada do scan.
