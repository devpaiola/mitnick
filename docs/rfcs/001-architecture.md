# RFC-001 — Arquitetura e limites de confiança

**Status:** aceito para o protótipo v0.1.0-dev. **Data:** 2026-10-25.

## Decisão

O produto começa como um binário Go local, com descoberta limitada a um diretório indicado pelo operador. O core entrega arquivos de texto delimitados aos scanners internos; cada scanner implementa `scanner.Scanner` e declara capacidades. O resultado é normalizado em `findings.Finding`, passa por deduplicação e threshold e pode ser serializado em terminal, JSON ou SARIF.

Não há plugins dinâmicos nem engine externa invocada pelo scan padrão. `doctor` apenas verifica presença de `gitleaks`/`osv-scanner`; presença não implica execução. O operador pode solicitar `--gitleaks`; nesse caso, o binário instalado recebe uma cópia temporária dos arquivos já descobertos e é limitado por timeout e tamanho de relatório. Nenhuma configuração do repositório escolhe o executável ou a configuração do Gitleaks. O OSV-Scanner ainda não está integrado.

A inteligência de dependências usa conectores Go próprios, não o executável OSV-Scanner: `mitnick intel update` consulta OSV para pacotes/versões resolvidos e salva a resposta no catálogo SQLite local. O scan consome esse cache sem rede. Os formatos suportados e as lacunas declaradas ficam em [`data-sources.md`](../data-sources.md).

## Fluxo

```text
diretório escolhido pelo usuário
  → discovery (exclusões, limites, cancelamento, sem seguir symlinks)
  → scanners code + agents concorrentes com timeout
  → opcional e explícito: Gitleaks instalado sobre a cópia dos arquivos descobertos
  → finding v1 + fingerprint + supressão auditável
  → threshold de política
  → terminal / JSON / SARIF
  → opcional: contexto sanitizado para Codex CLI ou Claude Code selecionado
```

## Limites

- O caminho raiz é escolhido na CLI; paths fora dele não são lidos. Symlinks internos são ignorados.
- Entradas do projeto, incluindo prompts e configs de agente, são dados não confiáveis.
- Nenhum shell, servidor, ferramenta MCP, package script ou comando do projeto é iniciado.
- A análise IA só começa com `--ai --ai-consent` ou confirmação equivalente na TUI. O Mitnick inicia apenas o CLI selecionado, envia contexto sanitizado por stdin e não passa a raiz do projeto como diretório de trabalho. Conta, modelo, roteamento e cobrança ficam sob controle do CLI.
- Codex e Claude Code rodam sem ferramentas disponíveis ao modelo e fora do alvo; falha em aceitar as opções restritivas não aciona modo alternativo. Configurações gerenciadas do CLI e o próprio binário permanecem sob autoridade do usuário/organização.
- Findings determinísticos e política são autoridade; a IA pode retornar somente observações consultivas estruturadas, vinculadas ao contexto e nunca executadas.

## Consequências

A arquitetura é simples e auditável, mas scanners e base de advisories têm cobertura limitada. Novas engines precisam de RFC/ADR com origem de binário, pinagem, isolamento, timeout, limites de output e semântica de erro antes de execução automática.
