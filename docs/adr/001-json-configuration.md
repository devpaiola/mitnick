# ADR-001 — Configuração JSON estrita

**Status:** aceita para v0.1.0-dev. **Data:** 2026-10-25.

## Decisão

Usar JSON versionado para `mitnick.json`, rejeitar campos desconhecidos e aceitar somente um objeto. Flags prevalecem sobre ambiente, que prevalece sobre arquivo. A seleção do cliente de IA fica em perfil privado separado; o Mitnick não armazena autenticação, endpoint ou modelo.

## Motivo

JSON é suportado pela biblioteca padrão Go, facilita validação estrita e evita adicionar parser de YAML ao núcleo local-first.

## Consequências

Configuração é simples e sem dependência de rede. Comentários e aliases de YAML não são suportados; mudança de schema exige incrementar `version` e documentar migração. Perfis BYOAI foram elevados à versão 2 ao substituir endpoints configuráveis por seleção de Codex/Claude; o usuário deve reconectar um CLI para recriar perfil antigo.
