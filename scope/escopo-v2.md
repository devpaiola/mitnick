# Mitnick — RFC-002: Vulnerability Intelligence & Detection Rules

> **Status:** Proposta para discussão  
> **Versão do documento:** 0.1  
> **Projeto:** Mitnick — Open Source Application & AI Agent Security  
> **Stack principal:** Go  
> **Modelo de IA:** BYOAI (Bring Your Own AI), opcional e controlado pelo cliente

## 1. Resumo executivo

O **Mitnick Vulnerability Intelligence** será o subsistema responsável por **coletar, atualizar, normalizar, correlacionar e disponibilizar conhecimento sobre vulnerabilidades e fraquezas de segurança** para os motores de análise do Mitnick.

Seu objetivo é permitir que o Mitnick:

1. Consulte taxonomias e fontes de vulnerabilidades reconhecidas, como OWASP, CWE, CVE, NVD, OSV e GHSA.
2. Relacione falhas às linguagens, frameworks, bibliotecas, versões, configurações e agentes de IA efetivamente presentes no projeto.
3. Distinga **vulnerabilidades conhecidas em dependências**, **padrões potencialmente inseguros no código** e **riscos de configuração/agentes**.
4. Apresente descrições técnicas acessíveis, referências oficiais, exemplos de código vulnerável, versões corrigidas e testes seguros.
5. Ofereça dados estruturados ao **Mitnick Scanner**, ao **Mitnick AI Analyst** e ao **Mitnick Validation**.
6. Continue funcionando **offline**, utilizando a última base sincronizada e informando sua data de atualização.

A ambição de longo prazo é possuir cobertura de inteligência para **todos os principais ecossistemas de linguagens**. Isso **não significa** que o MVP terá análise estática profunda para todas as linguagens: o suporte será expandido progressivamente, com cobertura declarada e mensurável.

## 2. Problema

As vulnerabilidades estão distribuídas entre bases com formatos, identificadores, classificações e frequências de atualização diferentes. Além disso:

- A identificação de uma **CVE** em uma biblioteca depende de informações corretas sobre **pacote, ecossistema e versão**.
- Uma **CWE** descreve uma fraqueza genérica; sua presença no código exige um detector e evidências próprias.
- Uma categoria **OWASP** agrupa riscos; não equivale, por si só, a uma vulnerabilidade presente no projeto.
- A gravidade (CVSS), a probabilidade de exploração (EPSS) e a exploração conhecida (CISA KEV) são sinais distintos.
- Um modelo de IA pode ajudar a interpretar o contexto, mas não substitui evidências técnicas.

O Mitnick precisa conectar esses conceitos sem misturá-los e sem produzir falsas afirmações de segurança.

## 3. Objetivos e não objetivos

### 3.1 Objetivos

- Criar um **catálogo local indexado** de conhecimento de segurança.
- Integrar **fontes oficiais e comunitárias relevantes**, com rastreabilidade.
- Associar identificadores **CVE, GHSA, OSV, CWE e OWASP** quando houver relações documentadas.
- Oferecer **consulta por linguagem, ecossistema, pacote, versão, identificador e tecnologia**.
- Disponibilizar **rule packs** versionados para detecção por linguagem e configuração.
- Armazenar **exemplos vulneráveis e seguros**, além de testes de regressão e demonstrações em ambiente isolado.
- Permitir **atualização incremental, cache, snapshots e operação offline**.
- Facilitar priorização usando contexto técnico e, quando disponíveis, dados de **CVSS, EPSS e CISA KEV**.
- Integrar opcionalmente a **IA do próprio cliente** para análise contextual e orientação de correção.

### 3.2 Não objetivos da primeira versão

- Espelhar obrigatoriamente todas as CVEs existentes no dispositivo do usuário.
- Afirmar cobertura SAST universal desde o primeiro lançamento.
- Executar exploits contra sistemas reais para comprovar falhas.
- Executar exemplos de terceiros sem isolamento e autorização explícita.
- Enviar automaticamente código-fonte ou segredos para provedores externos de IA.
- Certificar que um código está seguro porque o scan não encontrou problemas.
- Substituir revisão humana, pentest autorizado ou processos formais de gestão de vulnerabilidades.

## 4. Fundamentos: como os dados se relacionam

| Conceito | Função no Mitnick | Observação |
|---|---|---|
| **OWASP** | Organização de categorias de riscos (web, LLMs, agentes) | Taxonomia e orientação; não é catálogo de CVEs |
| **CWE** | Classificação de fraquezas de software | Ex.: CWE-89 (SQL Injection) |
| **CVE** | Identificação de vulnerabilidades publicadas em produtos/versões | Ex.: CVE-2021-44228 |
| **GHSA / OSV** | Avisos e registros de vulnerabilidades por ecossistema/pacote | Pode haver aliases para CVEs |
| **CVSS** | Métrica de severidade técnica | Não indica, isoladamente, probabilidade de exploração |
| **EPSS** | Estimativa de probabilidade de exploração no período definido pelo modelo | Sinal dinâmico de priorização |
| **CISA KEV** | Catálogo de vulnerabilidades sabidamente exploradas | Sinal forte para priorização |
| **CAPEC** | Padrões de ataque | Informação complementar para explicações e threat modeling |

**Regra de correlação:** OWASP → CWE → regras de detecção é uma relação conceitual possível. CVEs e avisos de dependências são registros específicos e deverão ser correlacionados separadamente, preservando a proveniência.

## 5. Fontes de dados e conectores

### 5.1 Fontes previstas

| Fonte | Uso principal | Estratégia | Prioridade |
|---|---|---|---|
| [MITRE CWE](https://cwe.mitre.org/data/downloads.html) | Fraquezas, definições e relações | Importação de dados estruturados versionados | P0 |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Classificações de riscos web | Mapeamento curado/versionado | P0 |
| [OWASP GenAI](https://genai.owasp.org/) | Riscos de LLMs e agentes | Mapeamento curado/versionado | P0 |
| [OSV.dev](https://osv.dev/) | Vulnerabilidades em pacotes e versões | API por pacote/versão e dados baixáveis | P0 |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Registros oficiais de CVEs | Importação incremental ou sob demanda | P0 |
| [NVD API](https://nvd.nist.gov/developers/vulnerabilities) | Enriquecimento e métricas de CVEs | API com cache e respeito a limites | P0 |
| [GitHub Advisory Database](https://github.com/advisories) | GHSA e avisos por ecossistema | Consulta estruturada conforme integração disponível | P0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploração conhecida | Sincronização do catálogo | P0 |
| [FIRST EPSS](https://www.first.org/epss/) | Priorização probabilística | Consulta/snapshot com data de referência | P1 |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | Recomendações de prevenção | Links e conteúdo curado, respeitando termos | P1 |
| [MITRE CAPEC](https://capec.mitre.org/) | Padrões de ataque | Importação e relações | P1 |

**Importante:** disponibilidade, termos de uso, limites de API, formatos de exportação, licenças de redistribuição e políticas de atualização serão validados durante a implementação de cada conector. Nem toda fonte permite espelhamento ou redistribuição irrestrita.

### 5.2 Contrato de um conector

Cada conector deverá:

1. Identificar a fonte e a versão ou data dos dados.
2. Fazer sincronização **incremental**, quando suportada.
3. Aplicar **timeouts, retries com backoff e limites de requisições**.
4. Validar estrutura, tamanho e integridade do conteúdo recebido.
5. Registrar origem, identificador original, horário de coleta e status de importação.
6. Resolver aliases e duplicatas sem perder o registro de origem.
7. Tratar registros alterados, rejeitados, retirados ou despublicados.
8. Evitar bloquear um scan caso a fonte remota esteja indisponível.

## 6. Arquitetura lógica

```text
                 FONTES DE INTELIGÊNCIA
       OWASP | CWE | CVE | NVD | OSV | GHSA
                CISA KEV | EPSS
                         |
                         v
              [Conectores / Sync]
                         |
                         v
       [Normalização + Aliases + Proveniência]
                         |
                         v
               [Catálogo Local]
               SQLite + snapshots
                         |
           +-------------+-------------+
           |             |             |
           v             v             v
     [Code Scanner] [Agent Scanner] [AI Analyst]
           |             |          BYOAI opcional
           +-------------+-------------+
                         |
                         v
              [Findings / Correlações]
                         |
                         v
       [Exemplos / Correções / Validação]
                         |
                         v
          CLI | JSON | SARIF | GitHub Actions
```

### 6.1 Subsistemas

**Intelligence Sync:** coleta e sincroniza fontes externas.  
**Knowledge Store:** consulta dados normalizados e índices locais.  
**Rule Registry:** catálogo versionado de regras e metadados de detecção.  
**Language Adapters:** identificam tecnologias e manifestos presentes.  
**Correlation Engine:** liga findings a fraquezas, avisos e risco contextual.  
**Example Registry:** organiza exemplos vulneráveis, corrigidos e testes.  
**AI Context Builder:** prepara apenas os trechos necessários para a IA do cliente.  
**Validation Engine:** registra e verifica a evidência e o resultado da correção.

### 6.2 Princípios técnicos

- Implementação principal em **Go**.
- Interfaces internas pequenas e modulares, com integração de scanners externos quando útil.
- **SQLite** para índice e cache local; possíveis exports JSON compactados.
- Atualizações separadas de análises: **o scan não exige internet**.
- Snapshots reproduzíveis; indicação de **idade dos dados** no relatório.
- Suporte a pacotes de atualização íntegros e assinados, conforme evolução da distribuição.
- Nenhum plugin ou regra remota executará código arbitrário como efeito da sincronização.

## 7. Modelo de dados proposto

Entidades principais:

- **Source:** fonte, licença/termos, versão, última sincronização e estado.
- **Weakness:** CWE, nome, descrição, relações e referências.
- **RiskCategory:** OWASP, versão da taxonomia e relação com CWEs.
- **Advisory:** identificador canônico, aliases (CVE/GHSA/OSV), resumo, referências e status.
- **AffectedPackage:** ecossistema, nome, intervalos afetados, eventos de correção e condições.
- **RiskSignal:** CVSS, EPSS, KEV, datas e fonte.
- **DetectionRule:** ID Mitnick, linguagem, motor, escopo, evidência mínima e mapeamentos.
- **Example:** linguagem, versão, fragmento vulnerável, versão corrigida e teste seguro.
- **Finding:** localização, evidência, origem, severidade, confiança, status e correlação.
- **SyncRun:** resultados, falhas, contadores, versões e duração da sincronização.

### 7.1 Exemplo ilustrativo de regra declarativa

```yaml
id: MITNICK-PY-0001
name: SQL Injection via SQL concatenado
version: 0.1.0
languages: [python]
category: injection
references:
  cwe: [CWE-89]
  owasp: [A05:2025]
default_severity: high
detection:
  engine: python-taint-analysis
  rule: sql-query-untrusted-input
examples:
  vulnerable: examples/python/sql-injection/bad.py
  secure: examples/python/sql-injection/good.py
  test: examples/python/sql-injection/test.py
```

Este é um **contrato proposto**, não uma regra funcional pronta. O identificador `python-taint-analysis` deverá corresponder a um motor existente e registrado; **YAML não poderá executar scripts arbitrários**.

### 7.2 Formato mínimo de um finding

```json
{
  "id": "finding-001",
  "rule_id": "MITNICK-PY-0001",
  "kind": "code-weakness",
  "title": "Possível SQL Injection",
  "severity": "high",
  "confidence": "medium",
  "status": "potential",
  "location": {"file": "app/users.py", "line": 18},
  "references": {"cwe": ["CWE-89"], "owasp": ["A05:2025"]},
  "evidence": "Entrada não confiável interpolada em uma consulta SQL",
  "detector": {"name": "python-taint-analysis", "version": "0.1.0"},
  "recommendation": "Utilizar consulta parametrizada"
}
```

**Estados de avaliação:** `confirmed`, `potential`, `unverified`, `not_applicable`, sempre com justificativa. Um achado emitido exclusivamente por IA não deve ser automaticamente classificado como `confirmed`.

## 8. Cobertura de linguagens e tecnologias

A implementação deverá separar dois eixos:

- **Dependency intelligence (SCA):** investigação de pacotes e versões vulneráveis, quando os dados do ecossistema estiverem disponíveis.
- **Code security (SAST):** análise de padrões de código, dependente de parser, regras ou scanner adequado à linguagem.

| Ecossistema | Insumos | Estratégia inicial |
|---|---|---|
| JavaScript / TypeScript | npm, pnpm, yarn e lockfiles | SCA + scanners/regras JS/TS |
| Python | PyPI, Poetry, uv e lockfiles | SCA + scanners/regras Python |
| Go | `go.mod`, `go.sum` | SCA + integração com govulncheck quando apropriado |
| Rust | Cargo, `Cargo.lock` | SCA + RustSec/avisos e regras Rust |
| Java / Kotlin | Maven, Gradle | SCA + regras JVM |
| C# / .NET | NuGet | SCA + regras C# |
| PHP | Composer | SCA + regras PHP |
| Ruby | RubyGems / Bundler | SCA + regras Ruby |
| Swift | SwiftPM | SCA + regras Swift |
| C / C++ | SBOM, Conan, vcpkg e outros | SCA onde houver identificação confiável + regras C/C++ |
| Configurações | Docker, Terraform, Kubernetes, CI/CD | Regras específicas de configuração |
| Agentes de IA | MCP, instruções e permissões de agentes | Auditoria estática e políticas próprias |

**Cobertura universal é objetivo, não promessa inicial.** O comando de scan sempre deve informar quais linguagens e verificações foram suportadas, executadas, ignoradas ou não disponíveis.

## 9. Biblioteca de exemplos e demonstrações seguras

Cada regra de segurança poderá possuir uma ficha com:

- Descrição e pré-condições da falha.
- Linguagens e frameworks afetados.
- Referências a OWASP, CWE e avisos relacionados.
- **Exemplo mínimo vulnerável** (reproduzível em laboratório).
- **Exemplo corrigido**, com justificativa.
- **Teste de regressão** para demonstrar a correção.
- Orientações de mitigação e links oficiais.
- Limitações de detecção e falsos positivos conhecidos.

### 9.1 Exemplo: CWE-89, SQL Injection em Python

**Vulnerável:**

```python
username = request.args["username"]
cursor.execute(
    f"SELECT * FROM users WHERE name = '{username}'"
)
```

**Corrigido (driver com placeholder `?`):**

```python
username = request.args["username"]
cursor.execute(
    "SELECT * FROM users WHERE name = ?",
    (username,)
)
```

A sintaxe de parâmetros depende do driver. O exemplo é ilustrativo e deve ser adaptado/testado no ambiente específico.

### 9.2 Segurança dos laboratórios

- Execução exclusivamente em **ambientes de teste isolados** e com autorização.
- Recursos limitados (CPU, memória, tempo, disco e rede).
- Sem acesso automático a credenciais ou dados reais.
- Testes focados em comprovar padrões e correções; não em exploração de alvos externos.
- Exemplos e instruções de terceiros tratados como **dados não confiáveis**.

## 10. Integração BYOAI

A IA é **opcional** e será fornecida/configurada pelo cliente (modelo local ou API externa). O Mitnick não hospedará nem custeará inferência no MVP.

### 10.1 Responsabilidades da IA

- Interpretar achados produzidos por scanners e regras.
- Investigar contexto de código com arquivos/trechos explicitamente autorizados.
- Explicar riscos e pré-condições de exploração de forma compreensível.
- Sugerir correções e testes de regressão.
- Ajudar a distinguir suspeitas, resultados não verificáveis e potenciais falsos positivos.

### 10.2 Controles obrigatórios

- Sem envio externo de código por padrão.
- Consentimento e configuração explícitos para provedores remotos.
- Mascaramento de segredos conhecidos antes de preparar contexto.
- Política de minimização de dados enviados ao modelo.
- Respostas estruturadas, validadas por esquema e tratadas como **não confiáveis**.
- Sem comandos arbitrários, alterações de arquivos ou desativação de políticas sem aprovação humana.
- Rastreabilidade do uso da IA: provedor, modelo, data, origem das evidências e limites da análise.

## 11. Interface CLI proposta

```bash
# Sincronizar a base de inteligência
mitnick intel update

# Ver estado, versões e data das fontes
mitnick intel status

# Consultar uma vulnerabilidade específica
mitnick intel show CVE-2021-44228

# Consultar uma fraqueza e exemplos em determinada linguagem
mitnick explain CWE-89 --lang python

# Verificar o projeto usando a base local
mitnick scan .

# Verificar com IA configurada pelo cliente
mitnick scan . --ai

# Gerar relatório estruturado
mitnick scan . --format sarif --output mitnick.sarif
```

Todos os comandos acima são **interfaces planejadas**, ainda não implementadas.

## 12. Priorização de achados

O Mitnick deve evitar reduzir todo o risco a um único score sem contexto. A priorização deverá considerar, quando disponível:

- Gravidade da vulnerabilidade (ex.: CVSS).
- Exploração conhecida (CISA KEV).
- Probabilidade de exploração (EPSS e data da estimativa).
- Confiança e qualidade da evidência da detecção.
- Versão instalada, intervalo afetado e eventual correção disponível.
- Alcançabilidade e exposição do componente, **quando demonstráveis**.
- Controles mitigadores e ambiente de implantação, se informados pelo usuário.

As fontes e limitações de cada sinal devem aparecer no relatório. Ausência de dados não equivale a ausência de risco.

## 13. Roadmap de implementação por fases

### Fase Intel 0 — Contratos e modelagem

**Escopo:** modelo de dados, fontes, IDs, aliases, estados e especificação de findings.

**Entregáveis:** RFC aprovada, structs/interfaces Go, esquema SQLite inicial, formatos de regras e fixtures.

**Critérios de aceite:** exemplos de OWASP, CWE e advisories podem ser representados sem perda dos IDs e da proveniência.

### Fase Intel 1 — Conectores básicos

**Escopo:** conectores para CWE, OWASP, OSV, CVE List V5, NVD, GitHub Advisory e CISA KEV, com limites e sincronização apropriados.

**Entregáveis:** mecanismo de importação, validadores, logs de sync e testes de contrato com fixtures.

**Critérios de aceite:** sincronizar dados, consultar registros e recuperar-se de falhas parciais sem corromper o catálogo.

### Fase Intel 2 — Catálogo local e modo offline

**Escopo:** indexação SQLite, consultas, cache, deduplicação, snapshots e atualização incremental.

**Entregáveis:** `mitnick intel update`, `status`, `show`; política de retenção e testes offline.

**Critérios de aceite:** consulta offline reproduzível; a CLI informa última sincronização e fontes incompletas.

### Fase Intel 3 — Detecção de linguagens e dependências

**Escopo:** identificação de projetos, manifestos, lockfiles, pacotes e versões; consultas a advisories compatíveis.

**Entregáveis:** adapters por ecossistema e correlação de dependências afetadas.

**Critérios de aceite:** fixtures com versões vulneráveis, corrigidas e desconhecidas geram resultados distintos sem inventar CVEs.

### Fase Intel 4 — Rule Packs e associação com scanners

**Escopo:** registro de regras, mapeamentos CWE/OWASP, motores implementados/integrados e testes de regressão.

**Entregáveis:** rule packs iniciais para código, configurações e agentes/MCP.

**Critérios de aceite:** cada achado exibe detector, regra, evidência e grau de confiança; cobertura desconhecida é declarada.

### Fase Intel 5 — Catálogo de exemplos e validação

**Escopo:** exemplos vulneráveis/corrigidos e testes seguros para as regras priorizadas.

**Entregáveis:** biblioteca de exemplos, comando `explain`, instruções de laboratório isolado.

**Critérios de aceite:** exemplos são versionados, documentados e testados, sem execução automática no repositório inspecionado.

### Fase Intel 6 — Priorização contextual e BYOAI

**Escopo:** enriquecimento por EPSS/KEV/CVSS, interpretação da IA do cliente e sugestões de patches.

**Entregáveis:** política de envio, contexto mínimo, saída estruturada e trilha de auditoria.

**Critérios de aceite:** modo sem IA totalmente funcional; nenhum envio externo não autorizado; correções exigem revisão.

## 14. MVP e entregáveis mínimos

O primeiro MVP público deve permitir:

1. Atualizar e consultar uma base local de inteligência.
2. Buscar ao menos um registro por **CVE, CWE ou ID de advisory**.
3. Analisar dependências dos ecossistemas iniciais com versões conhecidas.
4. Associar findings a CWE/OWASP **quando existir mapeamento fundamentado**.
5. Detectar ao menos um conjunto definido de regras de código e de agentes/MCP.
6. Exibir descrições, referências, evidências, recomendações e exemplos para as regras cobertas.
7. Emitir resultados em terminal, JSON e SARIF.
8. Funcionar offline com dados previamente sincronizados.
9. Utilizar IA local/remota somente quando ativada e autorizada pelo usuário.
10. Explicitar lacunas de cobertura, fontes desatualizadas e resultados não verificados.

## 15. Testes e métricas de qualidade

**Testes essenciais:**

- Fixtures com projetos vulneráveis, corrigidos e sem cobertura.
- Contratos dos conectores e validação contra mudanças de esquema.
- Importação incremental, deduplicação, aliases, erros e revogações.
- Testes de privacidade (não envio externo quando AI desativada).
- Testes para não executar código do projeto analisado.
- Fuzzing de parsers e dos importadores de dados.
- Testes de integridade do cache e recuperação de atualizações interrompidas.

**Métricas sugeridas:**

- Cobertura por ecossistema, scanner e regra.
- Precisão e taxa de falsos positivos por tipo de finding.
- Atualidade das bases e sucesso de sincronizações.
- Tempo de análise por tamanho de projeto.
- Percentual de achados com evidência, correção e exemplo.
- Taxa de consultas offline bem-sucedidas.

As metas numéricas deverão ser definidas a partir de benchmarks e conjuntos públicos de teste, não estimadas sem medição.

## 16. Riscos e mitigação

| Risco | Mitigação |
|---|---|
| CVEs duplicadas entre fontes | Aliases e IDs canônicos preservando a proveniência |
| Associação incorreta de uma CVE ao projeto | Matching rigoroso de ecossistema, pacote, versão e condições |
| Fontes fora do ar ou limitadas | Cache local, retry, backoff e degradação explícita |
| Base desatualizada | Indicador de freshness e sincronização separada |
| SAST superficial gerando falsos positivos | Confiança, evidências, testes e estados de avaliação |
| Regras de terceiros comprometidas | Validação, versionamento e não execução automática |
| Vazamento de código pela IA | BYOAI opt-in, minimização e proteção de segredos |
| Exemplos inseguros executados no projeto | Laboratório isolado e execução explícita/autorizada |
| Alto custo de suporte universal | Adapters graduais e matriz pública de cobertura |
| Restrições de licença das bases | Verificação jurídica/técnica por fonte antes de redistribuir |

## 17. Estrutura de repositório proposta

```text
mitnick/
├── cmd/mitnick/
├── internal/
│   ├── core/
│   ├── intelligence/
│   │   ├── connectors/
│   │   │   ├── cwe/
│   │   │   ├── osv/
│   │   │   ├── cve/
│   │   │   ├── nvd/
│   │   │   ├── ghsa/
│   │   │   └── kev/
│   │   ├── normalize/
│   │   ├── correlate/
│   │   ├── store/
│   │   └── sync/
│   ├── scanner/
│   ├── agents/
│   ├── ai/
│   ├── findings/
│   ├── rules/
│   └── reporter/
├── rules/
│   ├── code/
│   └── agents/
├── examples/
│   ├── python/
│   └── javascript/
├── testdata/
├── docs/
│   └── rfcs/
│       └── RFC-002-vulnerability-intelligence.md
└── go.mod
```

## 18. Decisões pendentes

- Escolha exata das primeiras linguagens com **SAST** (diferente de SCA).
- Estratégia de distribuição dos dados: snapshot embutido, download inicial ou consulta sob demanda.
- Modelo de assinatura e atualização dos rule packs.
- Critérios para elevar um finding de `potential` para `confirmed`.
- Padrão de compatibilidade de integrações com scanners externos.
- Política de versionamento e manutenção dos exemplos vulneráveis.
- Requisitos mínimos de armazenamento e memória da base local.

## 19. Recomendação de implementação

A ordem recomendada é **começar pelos contratos de dados e pelo catálogo local** antes de ampliar scanners e IA. O produto deve possuir quatro subsistemas independentes, porém integrados:

1. **Mitnick Intelligence:** conhecimento estruturado e atualizado.
2. **Mitnick Scanner:** detecção no código, dependências, configurações e agentes.
3. **Mitnick AI Analyst:** investigação contextual com modelo do cliente.
4. **Mitnick Validation:** testes seguros, evidências e revisão de correções.

O **Intelligence** é obrigatório para o funcionamento de vários recursos, mas **não deve depender** de um provedor de IA, de internet durante o scan ou de um scanner específico.

---

**Próximo artefato recomendado:** `RFC-003 — Data Model & Connector Contracts`, detalhando structs Go, esquema SQLite, interfaces de conectores, versionamento e políticas de sincronização.
