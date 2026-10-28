# Prontidão para v0.1.0

**Estado:** candidato local de implementação; publicação pública não aprovada nem concluída.

Este checklist mantém os critérios de [`scope/escopo-v1.md`](../scope/escopo-v1.md) e registra evidência local e dependências externas da entrega. O produto não declara cobertura completa nem ausência de vulnerabilidades.

## Fases e entregáveis

| Fase | Estado | Evidência local | Trabalho restante |
| --- | --- | --- | --- |
| 0 — definição | Parcial | RFC-001–004, ADR-001–003, threat model, backlog e política SECURITY preliminar. | Revisão independente, decisões de nome/licença e canal de reporte. |
| 1 — core e CLI | Implementada localmente | Comandos `scan`, `doctor`, `config`, `rules`, `report`, `version`; schema Finding 1.0; discovery delimitada por cancelamento, arquivos, entradas, bytes, tamanho e padrões de exclusão; config/report limitados e JSON sem chaves duplicadas; tratamento de sinais; testes de cancelamento, symlink, arquivo grande, path Unicode, config estrita, saída e código de retorno. | Testar com a matriz remota de SOs e toolchains mantidas. |
| 2 — code + agents | Parcial | Scanners unificados; fixtures seguras/vulneráveis; positivos e negativos para regras documentadas; fingerprints, evidência mascarada e supressão inline auditável; scan padrão não executa conteúdo; Gitleaks 8.16.0 opt-in copia somente arquivos descobertos, limpa o ambiente, usa redaction, limite de 30s/16 MiB e passa em testes; scan real deu zero findings Gitleaks no fixture seguro e um no vulnerável; snapshot offline revisado em 2026-10-25 cobre advisories selecionadas de lodash, axios, Next.js, React Server Components e minimist; arquivos MCP Gemini/Copilot têm testes de reconhecimento. | OSV-Scanner ainda não integrado; testar Gitleaks em versões/SOs adicionais, revisar o processo externo independentemente, ampliar formatos/stacks e medir falsos positivos em projetos de referência; snapshot npm segue selecionado. |
| 3 — TUI/BYOAI | Implementada localmente; integração real pendente | Bubble Tea por teclado; comandos `ai detect/list/connect/test`; seleção Codex/Claude e perfil privado v2 que guarda apenas o cliente; consentimento por scan; adaptadores CLI com ferramentas do modelo desativadas, contexto via stdin, isolamento de diretório, limites de entrada/saída e parser JSON estrito; testes com executáveis simulados. | Testar UI e versões atuais dos dois CLIs em Linux/macOS/Windows com contas de teste; validar roteamento e políticas organizacionais; limites de uso dependem da conta; redaction requer revisão independente. |
| 4 — integrações e robustez | Parcial | JSON/SARIF, Action composta, workflow exemplo, workflow de release com verificação de checksums e atestação de proveniência SLSA, instaladores shell/PowerShell, pacotes Linux/macOS/Windows amd64/arm64, SBOM SPDX 2.3 e SHA-256. | Workflows não executados em GitHub; SARIF não foi aceito por consumidor GitHub; matriz Linux/macOS/Windows e Go 1.26/1.27 ainda precisa de execução verde; instaladores precisam de teste em SOs reais; nenhuma release ou atestação foi publicada. |
| 5 — MVP público | Parcial | README, quickstart, suporte, changelog, contribuição, conduta, segurança, templates de issue, regras, fixtures e pacote local; repositório Git local inicializado e fluxo de release por tag preparado. | Ainda não há commit inicial, remote ou tag; clearance formal de marca, revisão jurídica de dependências/dados, canal privado SECURITY, configuração de labels, publicação e validação do processo de release continuam pendentes. |
| 6 — enforcement runtime | Fora do MVP | Registrado como pós-v0.1 em [`scope/escopo-v1.md`](../scope/escopo-v1.md). | Exige planejamento separado e nova revisão de ameaça. |

## Evidência de execução local

Na máquina disponível (Linux `amd64`, Go 1.26.8), passaram `go test ./...`, `go vet ./...` e `go test -race ./...`, com `GOPROXY=off`. Todos os pacotes de teste também foram compilados para Windows `amd64`, mas não foram executados nesse host Linux; a execução Windows continua pendente no CI. Fuzzing recente de três segundos passou para configuração (38.191 execuções), JSON sem chaves duplicadas (38.638), lockfile npm (71.450), semver (5.968), instruções/configuração de agentes (16.079), supressões (31.786), globs de exclusão (20.026), resposta/endpoint BYOAI (48.809), relatório do Gitleaks (129.425) e parser de limite monetário (56.560). A baseline cobre os fixtures e um self-scan do worktree Mitnick; benchmarks em projetos externos de referência continuam pendentes. Consulte [baseline](performance-baseline.md).

Os pacotes `linux`, `darwin` e `windows` para `amd64` e `arm64` são gerados localmente com nomes versionados e aliases estáveis para os instaladores; `SHA256SUMS` cobre ambos. Os instaladores `scripts/install.sh` e `scripts/install.ps1` escolhem plataforma/arquitetura, validam SHA-256 e instalam no PATH do usuário. Os pacotes contêm binário, documentação e SBOM SPDX 2.3. O SBOM lista módulos presentes nos metadados de build e usa `NOASSERTION` para licenças ainda não revisadas. Esses são artefatos de candidato local, não uma publicação.

O binário Linux empacotado respondeu `mitnick 0.1.0`; o fixture seguro foi escaneado com zero findings (a variável `PUBLISHABLE_KEY` é aceita) e o vulnerável com 25 findings, incluindo 13 resultados GHSA e o alerta de variável pública com `SECRET_KEY`. O mesmo caso gerou SARIF 2.1.0 com 25 resultados. Com `--fail-on high`, o fixture seguro retorna 0 e o vulnerável retorna 1; o relatório JSON continua válido e o erro de threshold fica separado no canal de erro do processo.

O runner local está em Go 1.26.8. A política oficial do Go mantém um release até haver dois releases principais mais novos; a publicação deve usar patches atuais e confirmar a matriz declarada no CI.

## Cobertura da RFC-002 — Vulnerability Intelligence

**Estado:** implementação parcial local. O catálogo SQLite, conectores OSV/CWE/KEV/CVE List/NVD/GitHub Advisory/EPSS, taxonomias OWASP curadas, comandos offline, adapters SCA iniciais e enriquecimento JSON/SARIF estão presentes. Testes de contrato usam respostas HTTP simuladas e cobrem aliases compartilhados, preservação de registros brutos, paginação, limites, retries e manutenção de cache anterior quando a atualização falha. Consulte a [RFC-005](rfcs/005-vulnerability-intelligence.md) e o [inventário de fontes](data-sources.md).

Ainda faltam adapters para vários manifests previstos, espelhamento/atualização incremental de CVE, assinatura de snapshots de regras, validação ampla com benchmarks públicos e revisão jurídica dos dados/fontes. O SCA só consulta versões que o parser consegue identificar com confiança; em particular, `go.mod` e `go.sum` são declarados sem suporte. A implementação não atesta alcance nem ausência de vulnerabilidades.

## Critérios de aceitação ponta a ponta

| Cenário | Estado local |
| --- | --- |
| Credencial simulada é localizada sem expor o valor na evidência | Teste positivo e negativo do scanner. |
| Dependência vulnerável recebe advisory, versão instalada e correção | Testes positivos e negativos nas fronteiras de lodash, axios, Next.js, React Server Components e minimist; advisory e intervalo são incluídos no finding. |
| Instrução de agente e config MCP suspeitas são reportadas sem execução | Testes unitários e teste de scan passivo com comando sentinela. |
| Gitleaks recebe somente arquivos descobertos, é opt-in e não vaza segredos do resultado | Teste de CLI com engine sentinela e teste local com Gitleaks 8.16.0; valor de segredo ausente da evidência. |
| Scan padrão não chama modelo | Teste com perfil Codex conectado e CLI sentinela; sem `--ai` o executável não inicia. |
| Revisão Codex/Claude e resposta maliciosa | CLIs simulados verificam flags restritivas, stdin, ausência do path do projeto, consentimento e autenticação; parser fechado rejeita patch, assessment `confirmed`, IDs/fingerprints/evidências/CWE/referências inventados. |
| TUI e descoberta de agentes | Testes do modelo cobrem navegação/resize e seleção; inventário consulta PATH sem iniciar binários. Interação manual e compatibilidade com CLIs reais seguem pendentes. |
| Projeto permanece byte a byte igual ao scan | Teste snapshot inclui source, AGENTS.md e `.mcp.json`, com e sem exportação segura. |
| Pull request bloqueia por threshold e envia SARIF ao GitHub | O CLI gera SARIF 2.1.0 válido como JSON e retorna o status esperado; o workflow e upload ainda não foram executados por GitHub. |

## Gatilhos de publicação ainda abertos

- Commit inicial e remote acessível, tag e canal para reporte privado configurados.
- CI verde para Linux, macOS e Windows `amd64` em Go 1.26 e 1.27; Action e SARIF aceitos em pull request de teste.
- Revisão independente de segurança; validação de licenças de código e dados; busca formal de marca nos mercados escolhidos.
- Compatibilidade dos CLIs reais em matriz, uso de limites rígidos da conta/organização, verificação da atestação SLSA na release pública e revisão final do SBOM.
- Ampliação do snapshot de advisories e benchmark em projetos de referência, ou decisão de release que documente a cobertura aceita.
