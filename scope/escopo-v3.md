# RFC-003 — Mitnick TUI & BYOAI Integrations

> **Nota de implementação (2026-10-26):** a seleção de provedores HTTP/modelos descrita nesta proposta foi substituída. A versão atual conecta Codex CLI ou Claude Code já autenticados; consulte [`docs/rfcs/006-tui-byoai.md`](../docs/rfcs/006-tui-byoai.md) e o fluxo atualizado no README.

> **Projeto:** Mitnick — Open Source Application & Agent Security  
> **Status:** Proposta para discussão  
> **Versão:** 0.1  
> **Data:** 2026-10-25  
> **Stack proposta:** Go, Cobra e Bubble Tea  
> **Escopo:** Interface terminal e integração com IA/agentes do próprio usuário  
> **Documentos relacionados:** RFC-001 — Core Architecture; RFC-002 — Vulnerability Intelligence & Detection Rules

---

## 1. Resumo executivo

O Mitnick terá uma **TUI (Terminal User Interface)** acessível pelo comando `mitnick menu`, complementada por subcomandos para uso em scripts e CI/CD. A interface permitirá configurar o projeto, executar verificações de segurança, consultar vulnerabilidades, explorar *findings*, gerir atualizações de inteligência e integrar agentes ou modelos de IA disponibilizados pelo próprio usuário (**BYOAI — Bring Your Own AI**).

**Decisão inegociável:** Mitnick é uma **ferramenta de auditoria, não de correção**. O Mitnick e suas integrações de IA **apenas identificam, contextualizam, classificam, explicam e reportam problemas**. Não geram patches, não alteram o código analisado e não executam correções.

A plataforma **não fornece modelo de IA, acesso gratuito a IA, crédito de API ou infraestrutura própria de inferência**. É possível utilizar o Mitnick inteiramente sem IA.

## 2. Objetivos

1. Fornecer uma TUI utilizável no terminal para operações principais, dispensando memorização de comandos.
2. Permitir **descoberta, configuração e teste** de agentes CLI já instalados, modelos locais e endpoints externos sob controle do usuário.
3. Manter *scans* determinísticos disponíveis sem configuração de IA.
4. Integrar resultados de Code Security, Agent Security e Vulnerability Intelligence em um fluxo único.
5. Oferecer apresentação consistente de severidade, evidência, confiança, origem e referências de cada achado.
6. Ser local-first, transparente quanto a acesso a arquivos, chamadas externas e processos iniciados.
7. Evitar dependências de um fornecedor específico: integrações são adaptadores substituíveis.
8. Preservar um modo não interativo para pipelines e automação.

## 3. Não objetivos e proibições

**Fora do escopo do Mitnick:**

- Aplicar correções automáticas ou interativas no repositório analisado.
- Gerar `git diff`, patches aplicáveis, PRs de correção ou comandos prontos para alterar arquivos.
- Autorizar um agente de IA a modificar o repositório, executar ferramentas de escrita ou operar um shell sem controle.
- Hospedar, treinar ou distribuir um modelo de IA proprietário.
- Extrair tokens, sessões ou credenciais armazenados por Codex, Claude Code e ferramentas similares.
- Presumir que um agente CLI instalado localmente executa inferência local.
- Executar *payloads*, exploits ou testes destrutivos contra alvos reais.
- Prometer cobertura integral de segurança ou garantia de inexistência de vulnerabilidades.

**Permitido:** explicações do risco, evidências, referências para boas práticas, versões afetadas, condições de exploração, e orientações conceituais de mitigação. **Não permitido:** execução de mitigação, escrita no projeto e geração de código de correção.

O Mitnick pode gravar **somente seus próprios** arquivos de configuração, índice, cache, logs e relatórios em locais explicitamente definidos. Essas gravações não podem modificar o projeto auditado.

## 4. Experiência do usuário

### 4.1 Inicialização

```bash
mitnick                 # Abre TUI somente se houver terminal interativo
mitnick menu            # Abre a TUI explicitamente
mitnick scan .          # Scan não interativo, sem IA por padrão
mitnick scan . --ai     # Habilita o provedor BYOAI já configurado
mitnick doctor          # Diagnóstico de ambiente
```

Se não houver terminal interativo, `mitnick` sem argumentos deverá mostrar ajuda e sair, sem bloquear CI. A TUI deverá funcionar em Linux, macOS e Windows em terminais compatíveis, com degradação graciosa quando não houver suporte a cores ou mouse.

### 4.2 Menu principal proposto

```text
┌─────────────────────────────────────────────────────┐
│ MITNICK                           Security Platform │
├─────────────────────────────────────────────────────┤
│ > Scan Project                                      │
│   Findings & Evidence                               │
│   AI Integrations                                   │
│   Agent Security                                    │
│   Vulnerability Intelligence                        │
│   Reports & Export                                  │
│   Policies & Privacy                                │
│   System Diagnostics                                │
│   Help                                              │
└─────────────────────────────────────────────────────┘
  ↑↓ navegar | Enter selecionar | Esc voltar | Q sair
```

### 4.3 Telas e responsabilidades

| Tela | Função | MVP |
|---|---|---|
| Scan Project | Selecionar caminho, escopo, verificações e IA opcional | Sim |
| Findings & Evidence | Lista filtrável, evidências, origem e referências | Sim |
| AI Integrations | Detectar, configurar, selecionar e testar provedores | Sim |
| Agent Security | Inspecionar riscos em arquivos de agentes/MCP | Sim |
| Vulnerability Intelligence | Atualizar bases, consultar CWE/CVE/OWASP, ver idade dos dados | Sim |
| Reports & Export | Exportar JSON, SARIF e relatório legível | Sim |
| Policies & Privacy | Limites, consentimentos, listas de exclusão, retenção | Sim |
| System Diagnostics | Diagnóstico de scanners, permissões e integrações | Sim |
| Histórico comparativo e tendências | Comparar auditorias anteriores | Pós-MVP |
| Dashboard remoto | Visualização hospedada / multiusuário | Fora do MVP |

### 4.4 Fluxo de análise

1. Usuário escolhe o diretório ou executa `mitnick scan <caminho>`.
2. Mitnick detecta linguagens, manifestos, ferramentas de agentes e configurações relevantes.
3. Scanners determinísticos e regras locais são executados.
4. Resultados são relacionados a CWE, OWASP, CVE/OSV/GHSA quando aplicável.
5. Se `--ai` estiver habilitado, o gerenciador de privacidade seleciona **somente o contexto necessário**, com aprovação de envio quando couber.
6. A IA examina evidências e apresenta **apenas observações estruturadas**.
7. O normalizador associa cada afirmação da IA à sua fonte e marca a confiança.
8. A TUI exibe o relatório, com indicação de verificações realizadas, ignoradas ou falhas.
9. O Mitnick não altera nenhum arquivo do projeto auditado.

## 5. Integração BYOAI: modalidades

| Modalidade | Exemplos | Como funciona | Observação de privacidade |
|---|---|---|---|
| Agente CLI instalado | Codex CLI, Claude Code | Adaptador invoca interface oficial não interativa, se compatível com perfil de segurança | Agente local pode contatar serviços externos |
| Modelo local | Ollama, LM Studio e endpoints locais compatíveis | Mitnick consulta endpoint administrado pelo usuário | Inferência pode permanecer local; depende da configuração |
| API do cliente | Provedores e endpoints compatíveis | Cliente fornece endpoint e credenciais por mecanismo seguro | Dados podem sair do equipamento; exige consentimento |
| Sem IA | Nenhum | Apenas detectores determinísticos | Nenhum dado é enviado a serviços de IA pelo Mitnick |

**Regras de implementação:**

- Não ativar IA por padrão.
- Não reutilizar credenciais privadas por leitura direta de arquivos internos de agentes.
- Para agentes CLI, usar autenticação que o próprio agente gerencia, quando suportada; não pressupor direitos de uso por assinatura.
- Descobrir comandos, versões e opções disponíveis sem ler segredos ou executar operações destrutivas.
- Não aceitar arbitrariamente qualquer binário ou argumento de shell sem validação e autorização.
- Um adaptador só é elegível para análise real se houver um modo verificado de **somente leitura e sem ferramentas mutáveis**, complementado por isolamento do processo quando necessário. Caso não seja possível garantir esses controles, apresentar o provedor como **indisponível para análise** e orientar que o usuário utilize outro conector seguro.
- Quando o adaptador puder acessar ferramentas externas/MCP, desabilitá-las ou restringi-las explicitamente; não confiar somente em instruções textuais.
- Configurar timeout, limite de tamanho do contexto, limite de requisições e cancelamento.
- Manter rastreabilidade do adaptador e da versão utilizados.

### 5.1 Detecção e configuração

Fluxo de `AI Integrations`:

1. **Detect providers** — procurar executáveis conhecidos no `PATH` e endpoints explicitamente configurados.
2. **Inspect capability** — verificar versão, modo não interativo, saída estruturada, restrições de ferramentas e viabilidade de somente leitura.
3. **Select provider** — escolher um provedor padrão opcional.
4. **Configure** — definir modelo, endpoint, limites e políticas disponíveis.
5. **Test connection** — consulta inofensiva, sem código do projeto e sem ferramentas, somente com consentimento para eventual acesso externo.
6. **Save** — salvar configuração não sensível; credenciais permanecem no mecanismo seguro escolhido.

Estados esperados: `not_detected`, `detected`, `needs_auth`, `unsupported_version`, `unsafe_capabilities`, `ready`, `error`.

### 5.2 Adaptadores iniciais

- **Codex CLI:** descobrir instalação e versão; utilizar apenas modos oficialmente disponíveis e compatíveis com execução sem alteração de arquivos, sem ferramentas de escrita e sem elevação de privilégios.
- **Claude Code:** descobrir instalação e versão; exigir perfil que impeça escrita, comandos e ferramentas não autorizadas.
- **Ollama:** consultar endpoint local configurado, modelos disponíveis e teste de geração simples.
- **API genérica:** conector opcional para endpoints configurados pelo usuário com política de tráfego explícita.

A sintaxe de argumentos de cada CLI depende da versão instalada. Não fixar comandos com garantias de segurança sem testes de compatibilidade por versão.

### 5.3 Privacidade, isolamento e ameaça por prompt injection

Arquivos do projeto são **entrada não confiável**. Comentários, README, prompts de agentes e configurações MCP não podem modificar a política de execução do Mitnick.

Controles obrigatórios:

- Compartilhamento mínimo de trechos e metadados; nunca enviar repositório inteiro por padrão.
- Redação de segredos conhecidos e recusa de envio se a filtragem for insuficiente.
- Consentimento por tipo de destino: local, CLI possivelmente remoto, API remota.
- Sem envio silencioso de código a terceiros.
- Sem acesso de escrita ao projeto pelo processo de IA; usar sandbox/permissões OS quando disponíveis e uma cópia restrita de contexto, em vez de entregar a raiz do repositório.
- Sem montagem de credenciais, home do usuário ou sockets de infraestrutura no ambiente restrito, quando puder ser evitado.
- Desabilitar ferramentas de execução, edição, acesso à rede adicional e MCP não necessário.
- Tratar respostas de IA como dados não confiáveis: esquema estrito, limites de tamanho e nenhuma execução de conteúdo retornado.
- Mostrar claramente o destino dos dados e registrar somente metadados não sensíveis da execução.

**Aviso de segurança:** um parâmetro chamado “read-only” no CLI de terceiro, isoladamente, não garante ausência de efeitos colaterais. O Mitnick precisa validar o comportamento de cada adaptador e aplicar controles adicionais. Se não for possível, deve desabilitar essa integração.

## 6. Modelo de resposta da IA

O AI Analyst é **somente consultivo**. Não há campo de patch, alteração de arquivo ou comando executável.

```json
{
  "finding_id": "MITNICK-2026-0001",
  "analysis_type": "contextual_review",
  "assessment": "potential",
  "summary": "Entrada externa pode alcançar uma operação sensível sem validação suficiente.",
  "evidence_refs": ["src/api/users.go:47-53"],
  "cwe_ids": ["CWE-89"],
  "confidence": "medium",
  "limitations": ["Não foi possível confirmar a origem de todos os parâmetros."],
  "references": ["https://cwe.mitre.org/data/definitions/89.html"]
}
```

Os identificadores, caminhos e referências devem ser validados contra o contexto realmente disponibilizado ao modelo. A IA não deve criar um novo `finding` como “confirmado” sem critérios verificáveis. A inexistência de achados da IA não implica segurança do projeto.

## 7. Comandos CLI propostos

```bash
mitnick menu
mitnick scan .
mitnick scan . --ai
mitnick scan . --format json --output ./mitnick-report.json
mitnick findings --severity high
mitnick ai detect
mitnick ai list
mitnick ai configure
mitnick ai test
mitnick intel update
mitnick intel show CVE-2021-44228
mitnick doctor
```

**Contratos importantes:**

- `scan` sem `--ai`: nenhuma chamada a provedores de IA.
- `--ai`: exige provedor pronto e configuração explícita; erro claro se ausente.
- `--output`: escreve apenas no local autorizado, nunca sobrescreve arquivos do projeto sem confirmação explícita.
- `intel update`: acessa fontes de inteligência configuradas; não é uma operação de IA.
- Subcomandos oferecem `--help` e comportamento estável para CI.
- TUI e CLI chamam **os mesmos serviços do Core**.

### 7.1 Códigos de saída sugeridos

| Código | Significado |
|---|---|
| `0` | Execução concluída; sem falhas acima do limiar configurado |
| `1` | Foram encontrados achados que violam a política definida |
| `2` | Erro de configuração, parâmetro ou ambiente |
| `3` | Falha operacional ou varredura incompleta |
| `130` | Interrompido pelo usuário, quando aplicável |

Os resultados não devem ser ocultados quando houver falha parcial; cada relatório precisa exibir o estado de cobertura.

## 8. Arquitetura em Go

```text
mitnick/
├── cmd/mitnick/            # Entrada CLI
├── internal/
│   ├── app/                # Casos de uso, compartilhados por CLI/TUI
│   ├── tui/                # Views, navegação e estado (Bubble Tea)
│   ├── cli/                # Comandos Cobra
│   ├── core/               # Orquestração
│   ├── scanner/            # Code/Agent scanners
│   ├── findings/           # Modelo e validação de resultados
│   ├── intelligence/       # Bases CWE, OWASP, CVE, OSV etc.
│   ├── ai/
│   │   ├── provider/       # Contrato BYOAI
│   │   ├── codex/          # Adaptador CLI
│   │   ├── claude/         # Adaptador CLI
│   │   ├── ollama/         # Adaptador local
│   │   └── http/           # Endpoints/API do cliente
│   ├── privacy/            # Política de contexto, consentimento
│   ├── sandbox/            # Isolamento e restrições de subprocessos
│   ├── config/             # Configuração, versões e validações
│   └── reporter/           # Console/JSON/SARIF
├── rules/
├── docs/rfcs/
└── go.mod
```

Tecnologias propostas: **Go**, **Cobra** para comandos, **Bubble Tea** para TUI, **Bubbles** para componentes e **Lip Gloss** para apresentação. As bibliotecas serão utilizadas conforme versões avaliadas durante a implementação.

### 8.1 Contrato conceitual de provedor

```go
type Provider interface {
    ID() string
    Detect(ctx context.Context) (CapabilityReport, error)
    Test(ctx context.Context, policy PrivacyPolicy) error
    Analyze(ctx context.Context, request AnalysisRequest) (AnalysisResponse, error)
}

type AnalysisRequest struct {
    FindingIDs   []string
    Context      []SanitizedEvidence
    Instructions string // Instruções fixas do Mitnick, nunca comandos executáveis
}

type AnalysisResponse struct {
    Observations []Observation // Sem patches ou ferramentas de edição
    ProviderID   string
    ModelID      string
}
```

O código acima descreve **interfaces conceituais**, não APIs públicas finalizadas.

### 8.2 Fronteiras de responsabilidade

- **Core:** agenda tarefas, resolve escopo, executa scanners e consolida resultados.
- **TUI:** apresenta formulários e resultados; não executa scanners diretamente.
- **Provider Manager:** detecta/valida adaptadores e suas capacidades.
- **Privacy Manager:** impõe limites e aprova o contexto permitido.
- **Sandbox Runner:** controla subprocessos e nega capacidades mutáveis.
- **Finding Engine:** diferencia evidência determinística de hipótese gerada por IA.
- **Reporter:** exporta relatórios sem armazenar segredos.

## 9. Configuração

Arquivo sugerido em diretório próprio do Mitnick, fora do projeto analisado. Um arquivo opcional por projeto poderá configurar *exclusões e políticas de scan*, mas nunca conceder permissão para executar comandos ou habilitar IA sem aprovação do usuário.

```yaml
version: 1
ai:
  enabled: false
  provider: "" # codex | claude | ollama | custom
  external_data_sharing: deny
  max_context_bytes: 20000
  timeout_seconds: 60
  allow_tools: false
  allow_file_writes: false
  allow_patch_generation: false
  redact_secrets: true
scan:
  target: "."
  include_code: true
  include_agents: true
  include_dependencies: true
  network_access: false
reports:
  format: terminal
  save_history: false
```

**Regras de segurança:** `allow_file_writes`, `allow_patch_generation` e `allow_tools` são **invariantes permanentemente falsas**, não opções habilitáveis no produto de auditoria. Caso estejam presentes com valor `true`, a configuração será rejeitada.

Credenciais devem ser providas via variáveis de ambiente ou armazenamento seguro do sistema; nunca salvas em texto puro no arquivo acima. Arquivos de configuração do projeto não podem mudar a política global de privacidade.

## 10. Design da TUI e acessibilidade

- Navegação somente por teclado, com atalhos visíveis.
- Contraste adequado; cores não são o único sinal de severidade.
- Mensagens objetivas e indicação de progresso/cancelamento.
- Filtros por severidade, tecnologia, origem, CWE/CVE e status.
- Detalhe do achado com localização, evidência mascarada, confiança e links oficiais.
- Separação visual entre **fato detectado**, **hipótese da IA** e **base externa**.
- Sem confirmação falsa de que um projeto está seguro.
- Avisos de custo/uso de terceiros antes de conectar a serviços pagos, quando aplicável.
- Logs sem prompts completos nem conteúdo sensível por padrão.

### 10.1 Exemplo de detalhe de achado

```text
MITNICK FINDING
────────────────────────────────────────────────────
ID: MITNICK-PY-0001        SEVERITY: HIGH
Title: Potential SQL Injection
File: app/repository.py:58
Source: static-rule / python-sast
Confidence: medium
References: CWE-89 · OWASP A05:2025

Evidence:
  Database query may interpolate untrusted input.

AI review (optional):
  Potential issue. Full dataflow could not be confirmed.
  Provider: user-configured / external-processing warning shown

Actions:
  [View evidence] [View references] [Export finding]

No modify / fix / patch action available.
```

## 11. Observabilidade e privacidade

O diagnóstico poderá registrar: duração do scan, versões dos scanners, estado dos conectores, erro genérico, total de arquivos e totais de achados. Não registrar por padrão conteúdo de código, prompts brutos, respostas completas de modelos, tokens ou chaves.

A configuração inicial terá **telemetria externa desativada**, histórico local opcional e política explícita de retenção. O usuário poderá inspecionar os destinos de rede autorizados.

## 12. Segurança e testes obrigatórios

### Segurança de subprocessos

- Invocar binários sem `sh -c` ou interpolação de comandos.
- Validar caminhos, versões e argumentos; evitar *PATH hijacking* em ambientes não confiáveis.
- Não executar scripts declarados pelo repositório analisado.
- Restringir acesso a sistema de arquivos/rede nos adaptadores, quando suportado.
- Rejeitar adaptadores sem capacidade verificável de somente leitura.

### Testes de privacidade e política

- `mitnick scan .` não invoca nenhum provedor de IA.
- `--ai` sem configuração não faz chamadas externas.
- Contexto enviado nunca inclui segredos conhecidos detectados pelos scanners.
- Entradas contendo prompt injection não alteram instruções, escopo ou ferramentas.
- Nenhuma resposta do modelo pode executar comandos, criar patches ou editar o projeto.
- Projeto analisado é byte a byte igual antes/depois do scan, excluindo alterações externas concorrentes.
- Subprocesso que tenta escrever é bloqueado e reportado como falha da integração.
- Falha do provedor de IA não invalida findings produzidos por scanners determinísticos.

### Testes de experiência

- Menu navegável sem mouse.
- Interrupção segura com Ctrl+C.
- Redimensionamento de terminal sem perda de estado crítico.
- CLI funcionando em ambiente não interativo.
- Relatórios reproduzíveis com mesmas entradas e mesmas versões de bases/regras (sem IA).

## 13. Roadmap por fases

### TUI-00 — Contratos e políticas

**Entrega:** contratos Go, política de somente leitura, matriz de capacidades dos provedores, especificação do esquema de observações e estrutura de configuração.  
**Critério de aceite:** nenhuma interface ou opção permite correção, patch ou escrita no repositório.

### TUI-01 — TUI básica e CLI

**Entrega:** `mitnick menu`, navegação, tela de scan, findings, doctor e reaproveitamento dos casos de uso do Core.  
**Critério de aceite:** usuário executa scan sem IA e navega por todos os findings.

### TUI-02 — Descoberta de agentes CLI

**Entrega:** detecção de Codex e Claude Code, checagem de versão/capacidades, status de integração e teste inofensivo.  
**Critério de aceite:** conectores incompatíveis são exibidos como indisponíveis; nenhum binário é invocado para análise sem o perfil restrito necessário.

### TUI-03 — Modelos locais e APIs do cliente

**Entrega:** Ollama, endpoint configurável, controle de contexto, consentimento, timeout e limites.  
**Critério de aceite:** IA desativada por padrão; usuário escolhe exatamente quando utilizar seu provedor.

### TUI-04 — Revisão contextual somente leitura

**Entrega:** observações vinculadas a findings, classificação de confiança, evidências e referências, sem código corretivo.  
**Critério de aceite:** IA só aponta e explica falhas; tentativas de edição/execução são impossibilitadas ou bloqueadas e registradas.

### TUI-05 — Consolidação para MVP público

**Entrega:** documentação, testes multiplataforma, mensagens de consentimento, ajuda e diagnósticos de segurança.  
**Critério de aceite:** TUI/CLI consistentes, operando com ou sem IA, com logs e exportações que respeitam a privacidade.

## 14. Critérios de aceite globais da RFC

- [ ] `mitnick menu` inicia uma TUI funcional em terminais suportados.
- [ ] É possível configurar um agente CLI compatível e um modelo local.
- [ ] É possível executar scan completo sem IA e sem chamadas de IA externas.
- [ ] Provedor de IA nunca é provisionado pelo próprio Mitnick.
- [ ] A TUI deixa claro quando um agente local utiliza inferência remota.
- [ ] O usuário visualiza findings de código, agentes e dependências.
- [ ] A IA fornece apenas observações estruturadas, com evidências e limitações.
- [ ] Não há geração de patches, edição de arquivos ou correção automatizada.
- [ ] Provedores sem isolamento adequado não podem ser usados para analisar repositórios.
- [ ] O Mitnick não coleta autenticações internas de agentes externos.
- [ ] É possível exportar relatórios em JSON e SARIF.
- [ ] A interface informa claramente scans incompletos e bases desatualizadas.
- [ ] Existem testes para prompt injection, exfiltração de dados e tentativas de escrita.

## 15. Questões em aberto

1. **Suporte mínimo multiplataforma:** quais versões de Linux, macOS, Windows e terminais serão oficialmente testadas?
2. **Sandbox dos agentes:** quais mecanismos de isolamento por sistema operacional serão exigidos antes de liberar adaptadores CLI?
3. **Modelos locais:** suportaremos apenas Ollama no MVP ou também um endpoint OpenAI-compatible local?
4. **Configuração:** arquivos por usuário, por projeto, ou composição com precedência estrita e política imutável?
5. **Custos:** como mostrar estimativa/limite de consumo, quando um provedor expuser dados confiáveis?

Essas decisões devem ser fechadas antes de considerar a implementação dos adaptadores CLI pronta para produção.

## 16. Resumo das decisões

| Tema | Decisão |
|---|---|
| Linguagem | Go |
| Interface | TUI com Bubble Tea + CLI Cobra |
| Comando principal da interface | `mitnick menu` |
| Oferta de IA | **Nenhuma**; BYOAI do usuário |
| Modos de IA | Agentes CLI, modelos locais, APIs configuradas pelo cliente |
| IA como requisito de scan | Não, estritamente opcional |
| Papel da IA | Apontar, investigar, explicar e classificar riscos |
| Correções e patches | **Proibidos** |
| Escrita no código analisado | **Proibida** |
| Permissões de agentes | Somente leitura com controles verificáveis |
| Scanner | Determinístico e independente de IA |
| Privacidade | Local-first; consentimento e minimização de dados |
| Estado da RFC | Proposta para discussão |

---

**Próxima etapa sugerida:** após aprovação desta RFC, implementar primeiro a camada compartilhada de casos de uso e a TUI sem IA; depois desenvolver os adaptadores de provedores com testes de isolamento e política de somente leitura.
