**DOCUMENTO DE PRODUTO  /  ESPECIFICAÇÃO INICIAL**

# MITNICK

Escopo completo e roadmap de implementação por fases

Plataforma open source de segurança para código, aplicações e agentes de IA, com análise opcional por modelos configurados pelo próprio cliente.

| DECISÃO | DIRETRIZ APROVADA |
| --- | --- |
| Produto | Mitnick — segurança de aplicações e agentes de IA |
| Linguagem principal | Go (Golang), incluindo CLI, core e integrações |
| Modelo de IA | BYOAI — IA do cliente; modo sem IA disponível |
| Abordagem | Local-first, scanners extensíveis, privacidade por padrão |
| Entrega inicial | CLI multiplataforma e integração com GitHub Actions |
| Licença proposta | Apache-2.0, mediante validação de compatibilidade |

_Versão: 1.0  |  Data: 25 de outubro de 2026_

_Status: escopo-base para implementação; estimativas, responsáveis e decisões pendentes serão refinados nas RFCs._

# 1. Resumo executivo

O Mitnick é uma plataforma de segurança para quem desenvolve software com auxílio de inteligência artificial, especialmente vibe coders, desenvolvedores independentes e pequenas equipes. Seu foco é identificar riscos, mostrar evidências e orientar correções sem exigir experiência prévia em segurança da informação.

O MVP será unificado: a mesma CLI verificará riscos de aplicações/código e riscos em arquivos de configuração de agentes e MCP. A camada de IA será complementar e utilizará exclusivamente modelos e credenciais escolhidos pelo usuário; o núcleo não dependerá de inferência para executar verificações essenciais.

# 2. Objetivos e premissas

## Objetivos

- Detectar e priorizar falhas comuns de código, dependências, segredos e configurações de agentes.

- Traduzir findings em orientações objetivas, com localização, evidência e recomendações acionáveis.

- Permitir revisão contextual e propostas de patch pela IA do cliente, sempre sob controle explícito.

- Funcionar localmente, em CI e sem conta obrigatória; admitir extensões e contribuições externas.

- Produzir resultados consistentes, reproduzíveis e exportáveis (terminal, JSON e SARIF).

## Premissas não negociáveis

- Implementação do núcleo e da CLI em Go; futuros módulos em Rust somente mediante necessidade demonstrada.

- Nenhum código enviado a serviços de IA externos sem habilitação e consentimento explícitos.

- Nenhum comando do repositório analisado executado automaticamente por padrão.

- Respostas de IA não podem sobrescrever evidências técnicas, desativar políticas ou aplicar patches sem revisão.

- O produto não promete ausência de vulnerabilidades nem substitui auditorias especializadas.

# 3. Público-alvo e casos de uso

| PERFIL | NECESSIDADE | FLUXO PRIORITÁRIO |
| --- | --- | --- |
| Vibe coder | Publicar apps gerados com IA com menos erros básicos. | Rodar scan local e corrigir findings. |
| Dev / freelancer | Revisar repositórios e dependências rapidamente. | Scan na CLI, exportação JSON/SARIF. |
| Equipe pequena | Impedir regressões em pull requests. | GitHub Actions com políticas de bloqueio. |
| Usuário de agentes | Auditar regras, permissões e configurações MCP. | Agent scan passivo de arquivos locais. |

# 4. Limites do produto

## Dentro do escopo do MVP

- Verificação estática de JavaScript/TypeScript e projetos web com Node.js, React e Next.js.

- Regras e inspeção de configurações pertinentes a Supabase, sem prometer cobertura completa de RLS em runtime.

- Detecção de segredos, dependências vulneráveis e configurações inseguras com engines existentes quando viável.

- Inspeção estática de instruções, permissões e definições MCP de agentes suportados.

- Integração opcional com um provedor local e um provedor externo de IA do cliente.

- Relatórios, política de severidade/threshold, CI e documentação para contribuintes.

## Fora do MVP

- Pentest ativo em sistemas de terceiros, exploração automática de falhas e monitoramento de produção.

- Interceptação ou bloqueio universal de chamadas de agentes em tempo real.

- Hospedagem própria de modelos de IA, SaaS obrigatório ou contas centralizadas.

- Correções autônomas sem aprovação e garantia/certificação de segurança.

- Suporte indistinto a toda linguagem, todo framework ou todo cliente de agentes.

# 5. Arquitetura de referência

Fluxo lógico: descoberta do repositório → scanners de código e agentes → normalização dos findings → políticas de risco → análise contextual opcional por IA → remediação → relatórios/verificação.

| CAMADA | RESPONSABILIDADE | CONTRATO / RESTRIÇÃO |
| --- | --- | --- |
| CLI | Comandos scan, config, doctor, rules e report. | Flags previsíveis; códigos de saída documentados. |
| Core | Descoberta, orquestração, concorrência e cancelamento. | context.Context; execução com timeouts. |
| Scanners | Código, segredos, dependências, configs e agentes. | Interface Go comum; capacidades declaradas. |
| Finding Engine | Normalização, deduplicação, severidade e evidência. | Identificadores estáveis e trilha de origem. |
| Policy Engine | Thresholds, exclusões justificadas e fail/pass. | Configuração versionável e auditável. |
| BYOAI | Seleção de provedor, contexto e análise assistida. | Opt-in; redaction; sem execução de ferramentas. |
| Reporters | Saída terminal, JSON, SARIF e sumário de CI. | Schema versionado e saídas sanitizadas. |

## Modelo universal de finding

Cada achado terá, no mínimo: id estável, id da regra, título, descrição, domínio (code/agent), severidade, confiança, estado (suspeita/validado/informativo), arquivo/localização, evidência sanitizada, origem, recomendação, fingerprint, timestamps e referências opcionais CWE/OWASP. O schema terá versão para garantir compatibilidade.

## Comandos previstos

- mitnick scan .  — Análise local unificada, sem IA por padrão.

- mitnick scan . --ai  — Executa também análise assistida, mediante configuração BYOAI.

- mitnick doctor  — Verifica ambiente, engines disponíveis e configurações.

- mitnick rules list  — Lista regras disponíveis e seu escopo.

- mitnick scan . --format sarif  — Exporta relatório consumível pelo ecossistema de CI.

## Política de execução e de dados

- Repositório, instruções de agentes e textos retornados por ferramentas são conteúdo não confiável.

- Sem executar scripts do projeto, iniciar servidores ou contatar endpoints arbitrários no scan padrão.

- Sem leitura de arquivos fora do escopo autorizado; respeitar exclusões e evitar seguir symlinks perigosos.

- Isolar processos auxiliares, limitar recursos e sinalizar dependências de binários externos.

- Na análise com IA, aplicar minimização, mascaramento de segredos, registro de consentimento e limites de custo/requests.

# 6. Roadmap por fases

As fases são marcos de entrega, não datas prometidas. A ordem prioriza contratos estáveis e um percurso completo de segurança antes da expansão. A duração depende do tamanho e da dedicação da equipe.

| FASE | MARCO | RESULTADO ESPERADO |
| --- | --- | --- |
| 0 | Definição / RFCs | Escopo técnico, contratos, threat model e governança. |
| 1 | Fundação Go / CLI | CLI funcional, core, config e findings. |
| 2 | Segurança unificada | Scanners iniciais de código e agentes no mesmo fluxo. |
| 3 | BYOAI | Modelos do cliente, análise contextual e controles de privacidade. |
| 4 | Integrações / qualidade | GitHub Actions, formatos, testes e hardening. |
| 5 | Release MVP | Versão pública v0.1.0, docs e processo de contribuição. |
| 6 | Evolução pós-MVP | Proteções runtime, mais stacks e extensibilidade avançada. |

# Fase 0  |  Definição e arquitetura

**PRÉ-REQUISITO PARA IMPLEMENTAÇÃO**

Transformar a visão em contratos implementáveis, com limites de confiança, prioridades e critérios de qualidade explícitos.

## Escopo de execução

- Escrever RFC-001 (arquitetura), RFC-002 (finding schema), RFC-003 (políticas) e RFC-004 (BYOAI e privacidade).

- Definir suporte mínimo de SO/arquitetura e a política de distribuição de scanners externos.

- Modelar ameaças: repositório malicioso, prompt injection, vazamento de segredos, abuso de CI e plugins inseguros.

- Estabelecer guias de contribuição, convenções Go, testes, dependências e licenciamento.

- Verificar disponibilidade e possíveis restrições de uso do nome Mitnick antes do lançamento público.

## Entregáveis

- Documentos RFC e ADR, mapa de módulos, backlog priorizado e matriz de riscos.

- Esqueleto do repositório e política SECURITY.md preliminar.

## Critérios de aceite / saída

- Interfaces e limites do MVP aprovados e registrados.

- Demonstração de fluxo de dados e ameaças com mitigação designada.

- Nenhuma decisão crítica de privacidade deixada implícita.

_DEPENDÊNCIAS  Nenhuma. É a fase de preparação do produto._

# Fase 1  |  Core e CLI em Go

**BASE EXECUTÁVEL DO MITNICK**

Criar a fundação executável para scanners, políticas e relatórios, sem depender de IA ou serviços remotos.

## Escopo de execução

- Inicializar módulo Go, CLI Cobra e comandos scan, doctor, version e config.

- Implementar discovery de arquivos com regras de exclusão e prevenção de path traversal/symlink escape.

- Definir interface Scanner e registro de capacidades; orquestrador concorrente com cancelamento/timeout.

- Criar schema de finding, deduplicação, normalização e critérios de severidade/confiança.

- Criar arquivo mitnick.yaml (ou equivalente), validação e precedência CLI > env > config.

- Implementar reporter de terminal e JSON, logs sem segredos e política básica de exit codes.

## Entregáveis

- Binário mitnick executando um scanner de demonstração sem rede.

- Core e interfaces públicos internamente documentados, testes unitários e fixtures.

- Comandos básicos, configuração e relatório JSON versionado.

## Critérios de aceite / saída

- mitnick scan . produz findings determinísticos em um projeto fixture.

- O scan padrão não executa código do repositório nem faz requisição de IA.

- Erros, timeouts, cancelamento e códigos de saída são cobertos por testes.

_DEPENDÊNCIAS  Contratos, threat model e convenções da Fase 0._

# Fase 2  |  Code Security + Agent Security

**PRIMEIRA ENTREGA UNIFICADA DE SEGURANÇA**

Oferecer cobertura útil e verificável nos dois pilares do produto usando o mesmo pipeline.

## Escopo de execução

- Code: detecção de segredos com mascaramento; auditoria de dependências e padrões estáticos prioritários.

- Code: reconhecer JS/TS, Node.js, React/Next.js e configs/migrações Supabase com regras delimitadas.

- Agents: localizar instruções e configurações de clientes suportados; auditar permissões e ferramentas declaradas.

- Agents: analisar configurações MCP, permissões excessivas e comandos potencialmente perigosos, sem execução.

- Criar adaptadores para Gitleaks, OSV-Scanner e/ou outras engines com isolamento e versões testadas.

- Adicionar fixtures vulneráveis/seguras, provas de regressão, suppressions justificadas e fingerprint.

## Entregáveis

- Scanners iniciais code e agent integrados ao mitnick scan.

- Pacote de regras com documentação e casos positivos/negativos.

- Relatório que distingue evidência confirmada, hipótese e informação.

## Critérios de aceite / saída

- Fixtures detectam credencial exposta, dependência conhecida vulnerável e configuração de agente arriscada.

- MVP executa verificação de código + agentes na mesma CLI, sem IA.

- Falsos positivos são registrados e há mecanismo auditável de exclusão.

_DEPENDÊNCIAS  Fase 1. O uso de binários externos deve ser explicitado em doctor e na instalação._

_NOTA  Não incluir exploração ativa, invasão de alvos nem execução automática de comandos declarados por agentes._

# Fase 3  |  AI Analyst (BYOAI)

**CAMADA INTELIGENTE CONTROLADA PELO CLIENTE**

Acrescentar análise contextual opcional sem transferir confiança ou execução arbitrária ao modelo.

## Escopo de execução

- Criar interface Provider em Go; integrar pelo menos um endpoint local (ex.: Ollama) e um remoto configurável.

- Implementar configuração de credenciais fora de texto puro, seleção de modelo e verificação de conectividade.

- Criar context builder para enviar somente trechos autorizados e necessários, com redaction de segredos.

- Definir prompt templates versionados e schemas estruturados para avaliação de risco e remediação.

- Adicionar limites de tokens, custo/requests e timeout; registrar destino e metadados sem guardar conteúdo sensível.

- Gerar sugestões e patches em diff não aplicados; exigir revisão humana e re-scan após correção.

## Entregáveis

- mitnick scan . --ai operando com os modelos configurados pelo cliente.

- Política documentada de consentimento, minimização e retenção de dados.

- Rastreamento da origem das conclusões da IA, suas incertezas e evidências.

## Critérios de aceite / saída

- Sem --ai ou configuração equivalente: zero chamadas a modelos, garantido por teste.

- Segredos conhecidos são mascarados antes de qualquer envio externo.

- Uma instrução maliciosa em arquivo analisado não altera política nem aciona ferramentas.

- Saída do modelo é tratada como sugestão, não como finding confirmado automaticamente.

_DEPENDÊNCIAS  Fase 2, schema de findings e threat model de dados._

# Fase 4  |  Integrações, relatórios e robustez

**QUALIDADE OPERACIONAL ANTES DO LANÇAMENTO**

Tornar o produto confiável em máquinas de desenvolvedores e pipelines de CI.

## Escopo de execução

- Implementar reporter SARIF, sumário de execução, códigos de saída por threshold e configurações de CI.

- Criar GitHub Action reutilizável e exemplo de workflow com permissões mínimas.

- Executar matriz de testes em Linux, macOS e Windows para ambientes suportados.

- Testar timeout, arquivos grandes, symlinks, paths Unicode, paralelismo e erros de engines externas.

- Aplicar fuzzing nos parsers críticos e benchmark baseline de tempo/memória em projetos de referência.

- Definir checksum, assinatura/reprodutibilidade quando viável e SBOM das distribuições.

## Entregáveis

- Action, reporter SARIF e pacotes multiplataforma em versão candidata.

- Relatório de compatibilidade, performance de referência e plano de hardening.

## Critérios de aceite / saída

- Pull request de teste falha/passa conforme threshold documentado.

- Instalação e execução passam nos SOs declarados como suportados.

- Casos de erro não expõem segredo, não quebram JSON e não geram sucesso falso.

_DEPENDÊNCIAS  Fases 1–3. A qualidade e os testes começam antes e continuam durante toda a execução._

# Fase 5  |  MVP open source v0.1.0

**PRIMEIRA PUBLICAÇÃO PÚBLICA**

Disponibilizar uma release utilizável, auditável e fácil de instalar, documentando honestamente as limitações.

## Escopo de execução

- Consolidar README, quickstart, referência da CLI, configuração BYOAI e matriz de suporte.

- Publicar CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, changelog e guia de regras/plugins.

- Validar licença e dependências, uso do nome, release notes e changelog de breaking changes.

- Gerar releases e checksums; publicar exemplos de scans locais e GitHub Actions.

- Criar issues com etiquetas, templates de bug/feature e políticas de manutenção.

- Executar revisão final de segurança da cadeia de build e dos fluxos BYOAI.

## Entregáveis

- Repositório público e tag v0.1.0 com binários e documentação.

- Projetos fixture, exemplos CI, lista pública de limitações e canal de reporte responsável.

## Critérios de aceite / saída

- Um usuário novo instala, roda scan, entende os resultados e exporta relatório.

- Um usuário novo configura IA local ou externa somente se desejar.

- Checklist de segurança, QA, documentação e licença concluído.

_DEPENDÊNCIAS  Fases 0–4 e decisões abertas de nomenclatura, licença e suporte._

# Fase 6  |  Expansão e proteção ativa

**PÓS-MVP / PLANEJAMENTO SEPARADO**

Evoluir de auditoria estática para políticas aplicáveis durante a operação de agentes, sem comprometer o núcleo local-first.

## Escopo de execução

- Projetar hooks/gateway para pré-autorizar ações de agentes e ferramentas MCP.

- Aplicar políticas para permissões, comandos e destinos de rede em integrações explicitamente suportadas.

- Adicionar novos ecossistemas de linguagem, frameworks e agentes por plugins.

## Entregáveis

- RFC de runtime enforcement, protótipos isolados e roadmap v0.2+.

- Modelo de APIs de plugin estabilizado e catálogo gradual de integrações.

## Critérios de aceite / saída

- Enforcement opt-in, testes de bypass/fail-safe e limites de interceptação documentados.

_DEPENDÊNCIAS  MVP estável, telemetria voluntária ou feedback comunitário e revisões de ameaça._

# 7. Matriz de prioridade e escopo

| CAPACIDADE | PRIORIDADE | MARCO |
| --- | --- | --- |
| CLI Go, config, core, findings e reporter JSON | P0 | F1 |
| Secret scan e dependency scan | P0 | F2 |
| Regras de código web + detecção de configurações inseguras | P0 | F2 |
| Agent/MCP static audit | P0 | F2 |
| BYOAI: um endpoint local + um remoto, opt-in | P0 | F3 |
| Remediação e sugestão de patch não aplicada | P0 | F3 |
| SARIF e integração GitHub Actions | P0 | F4 |
| Binários multiplataforma e documentação | P0 | F5 |
| Mais stacks, mais scanners e integrações com IDE | P1 | Pós-v0.1 |
| Runtime agent enforcement e dashboard local | P2 | F6 / RFC |

# 8. Requisitos não funcionais

| DIMENSÃO | REQUISITO |
| --- | --- |
| Segurança | Input não confiável por padrão, least privilege, sanitização e isolamento de engines externas. |
| Privacidade | Sem upload automático; consentimento do provedor; segredos mascarados e não registrados. |
| Resiliência | Timeouts, cancelamento, erros parciais explícitos e nenhuma aprovação falsa. |
| Performance | Concorrência limitada e benchmark documentado; metas quantitativas definidas após baseline F1/F2. |
| Portabilidade | Linux, macOS e Windows nas arquiteturas declaradas; dependências externas sinalizadas. |
| Qualidade | go test, fuzzing/parsers, CI, fixtures e revisão de segurança pré-release. |
| Extensibilidade | Interfaces estáveis, schema versionado e adaptadores em vez de acoplamento a fornecedores. |
| Acessibilidade | Mensagens legíveis sem cor, explicações acessíveis e documentação em português inicialmente. |

# 9. Métricas de acompanhamento

- Cobertura: número de classes de risco com fixtures positivas/negativas, separadas por code e agent.

- Qualidade dos resultados: taxa de falsos positivos por regra prioritária e porcentagem com evidência/localização.

- Operação: duração, pico de memória, taxa de erro e estabilidade por SO em projetos de referência.

- BYOAI: zero chamadas externas no modo desligado; falhas de redaction detectadas por testes.

- Usabilidade: conclusão do fluxo instalar → scan → entendimento → re-scan em projeto exemplo.

# 10. Critérios globais de pronto (Definition of Done)

- Mudança versionada e documentada; testes automatizados compatíveis com o risco da alteração.

- Sem logs de tokens ou snippets sensíveis; arquivos não confiáveis não são executados.

- Finding tem origem rastreável e evidência suficiente; sugestões da IA estão identificadas.

- Falha de engine externa ou de provedor BYOAI é reportada sem mascarar lacunas de cobertura.

- Toda regra nova inclui teste verdadeiro-positivo, teste verdadeiro-negativo e documentação.

- Todo suporte anunciado tem fixture ou teste de integração correspondente.

- Dependências, licenças e artefatos distribuídos são revisados antes da release.

# 11. Testes de aceitação ponta a ponta

| CENÁRIO | ESPERADO |
| --- | --- |
| Repositório com chave simulada exposta | Detectar, localizar, mascarar e orientar rotação/revogação. |
| Dependência com advisory de teste | Indicar pacote, versão, advisory e ação possível. |
| Arquivo de agente com permissão excessiva | Reportar risco e contexto sem executar a ferramenta declarada. |
| Configuração MCP suspeita | Identificar configuração/command/escopo de acesso em análise passiva. |
| Scan sem configuração de IA | Concluir análise estática sem chamar provedores. |
| Scan com IA local ativada | Produzir revisão contextual separada de findings determinísticos. |
| Scan com IA externa ativada | Enviar somente contexto permitido/mascarado; registrar destino e limitação. |
| PR com finding acima do threshold | GitHub Action retorna status configurado e SARIF válido. |
| Arquivo malicioso com instruções para IA | Instruções tratadas como dado; sem execução nem mudança de política. |

# 12. Riscos e mitigação

| RISCO | MITIGAÇÃO PLANEJADA |
| --- | --- |
| Escopo amplo demais para o MVP | Unificação no pipeline; apenas regras estáticas prioritárias em cada domínio. |
| IA alucina vulnerabilidades | Classificar confiança/origem, preservar evidências e exigir validação. |
| Vazamento de código ao modelo | Opt-in, minimização de contexto, redaction e configuração explícita. |
| Scanner externo cria novo vetor de ataque | Versões fixadas, timeouts, execução controlada e origem verificada. |
| Muito ruído / falsos positivos | Fixtures negativas, thresholds, suppressions justificadas e tuning. |
| Nome/licença conflita com terceiros | Verificação jurídica/marca e compatibilidade antes da publicação. |

# 13. Decisões em aberto e próximas ações

## Decisões pendentes de validação

- Confirmar disponibilidade do nome Mitnick e o tratamento de marca e identidade pública.

- Validar licença Apache-2.0 conforme licenças de bibliotecas, regras e motores acoplados.

- Definir SOs/arquiteturas mínimos, versões Go suportadas e política de distribuição dos binários auxiliares.

- Selecionar a primeira lista fechada de arquivos/agentes e um provedor externo para teste BYOAI.

- Fixar semântica de exit codes, formato de configuração e regra default de bloqueio em CI.

- Validar benchmark de referência e metas quantitativas após implementar o scanner real.

## Backlog imediato — ordem recomendada

| ORDEM | ATIVIDADE | ARTEFATO |
| --- | --- | --- |
| 1 | Escrever RFC-001 arquitetura + trust boundaries. | docs/rfcs/001-architecture.md |
| 2 | Definir schema v1 de Finding e interface Scanner. | internal/findings e internal/scanner |
| 3 | Criar scaffold Go, Cobra, go test e CI. | cmd/mitnick, go.mod, workflow |
| 4 | Implementar walk seguro e reporter JSON/terminal. | mitnick scan . |
| 5 | Criar 3 fixtures: segredo, dependência e agente/MCP. | testdata/ |
| 6 | Conectar scanners e primeira matriz de regras. | MVP estático unificado |
| 7 | Especificar contexto e consentimento BYOAI. | RFC-004 e adaptadores |

## Estrutura proposta de repositório

mitnick/
├── cmd/mitnick/          # CLI e ponto de entrada
├── internal/core/        # Orquestração e execução
├── internal/scanner/     # Contratos e adaptadores
├── internal/findings/    # Schema e deduplicação
├── internal/code/        # Regras de aplicações
├── internal/agents/      # Regras de agentes / MCP
├── internal/ai/          # BYOAI, redaction, contexto
├── internal/policy/      # Thresholds e exceções
├── internal/reporter/    # Terminal, JSON e SARIF
├── rules/                # Regras versionadas
├── integrations/github/  # GitHub Action
├── testdata/             # Fixtures seguras e vulneráveis
├── docs/rfcs/            # Decisões arquiteturais
└── go.mod

## Encerramento

O primeiro compromisso de entrega é o scan unificado e verificável de código e agentes. A análise por IA reforça esse diagnóstico, mas não o substitui. O Mitnick deve ser seguro na forma como analisa outros projetos, antes de prometer segurança a quem o utiliza.
