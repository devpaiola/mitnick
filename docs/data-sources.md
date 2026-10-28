# Fontes e cobertura de inteligência

Mitnick mantém um catálogo SQLite local para dados de vulnerabilidades. Os conectores são executados apenas por `mitnick intel update`; `scan`, `intel status`, `intel show` e `explain` não consultam a rede. Uma falha de sincronização é mostrada como incompleta e não impede o uso dos registros locais anteriores.

## Atualização e consulta

```sh
# Atualiza o catálogo CWE e o snapshot completo do CISA KEV
mitnick intel update

# Consulta OSV para versões exatas encontradas nos lockfiles suportados
mitnick intel update .

# Atualiza feeds globais e consulta fontes por CVE
mitnick intel update --id CVE-2021-44228

# Busca um GHSA e advisories GitHub associadas a uma CVE
mitnick intel update --source github-advisory --id GHSA-xxxx-xxxx-xxxx

# Usa o catálogo local; estes comandos são offline
mitnick intel status
mitnick intel show CVE-2021-44228
mitnick explain CWE-89 --lang python
```

`--source all` é o padrão: atualiza CWE e CISA KEV e, se um diretório for informado, consulta OSV para as dependências com versão resolvida. CVE List V5, NVD, GitHub Advisory e FIRST EPSS são consultas sob demanda. Com `--id CVE-...`, todas as fontes aplicáveis à CVE são consultadas; com `--id GHSA-...`, só GitHub Advisory usa o identificador. Se `--source` selecionar um conector sob demanda, `--id` é obrigatório. `--source osv` exige um diretório.

O catálogo padrão fica em `mitnick/intelligence.sqlite` no diretório de cache do usuário (`os.UserCacheDir`). Use `--db caminho` para selecionar outro arquivo. O banco e os diretórios privados padrão usam permissões restritas em sistemas Unix; um banco customizado conserva as permissões do diretório pai e protege o arquivo SQLite. Não versione o banco local: ele pode conter dados brutos de fontes consultadas.

## Conectores

| Fonte | Dados sincronizados | Escopo e limites |
| --- | --- | --- |
| MITRE CWE | ID, nome, descrição e versão do catálogo XML | Snapshot completo importado em uma transação; limites de tamanho/expansão; mapeamentos OWASP do Mitnick permanecem curados e separados. |
| OWASP Top 10 | Categorias da edição 2025 | Categorias e mapeamentos curados no pacote do Mitnick; não são advisories nem prova de vulnerabilidade. |
| OWASP GenAI | Categorias LLM e Agentic 2026 | Taxonomias curadas e versionadas; não são detectores automáticos. |
| OSV | Advisories para ecossistema, pacote e versão exatos | Consulta batch por projeto; suporta paginação e cache local. Não espelha todo o banco OSV. |
| CVE List V5 | Registro oficial de uma CVE, com descrição, fraquezas, datas e referências | Busca sob demanda por ID; mantém o JSON de origem no catálogo. |
| NVD API 2.0 | CVSS, CWE, status, descrição, referências e sinal KEV quando informado | Busca sob demanda por CVE; a chave opcional `NVD_API_KEY` é enviada somente ao NVD. |
| GitHub Advisory Database | GHSA/CVE, pacote, intervalo e versões corrigidas, CWE e CVSS | Busca por GHSA ou por CVE; uma CVE pode retornar diversos GHSAs, preservados como registros de origem distintos. `GH_TOKEN` ou `GITHUB_TOKEN` é opcional. |
| CISA KEV | Snapshot do catálogo de vulnerabilidades exploradas, com data e sinal `kev` | Feed completo; nenhum pacote é inferido a partir do produto do fornecedor. |
| FIRST EPSS | Score e percentil com data de referência | Busca sob demanda por CVE; armazenado como sinal probabilístico independente de CVSS e KEV. |
| GitHub Advisory embutido | Advisories npm selecionadas | Snapshot pequeno usado pelo scanner sem sincronização; inventário e atribuição em [`advisory-snapshot.md`](advisory-snapshot.md). |

Todos os conectores aplicam timeout, limite de tamanho e validação estrutural. APIs com suporte a retry repetem erros de rede, HTTP 5xx e 429 com espera limitada; registros remotos não podem escolher comandos ou regras executáveis. A CLI não baixa rule packs executáveis.

## Adaptadores de dependências

O scanner lê arquivos passivamente e não executa package managers. Adaptadores atuais:

| Arquivo | Ecossistema | Versão usada |
| --- | --- | --- |
| `package-lock.json`, `npm-shrinkwrap.json` | npm | Versão resolvida do lockfile |
| `requirements.txt` | PyPI | Somente requisitos com `==` |
| `Cargo.lock` | crates.io | Versão resolvida de cada pacote |
| `composer.lock` | Packagist | Versão resolvida de pacotes normais e de desenvolvimento |
| `Gemfile.lock` | RubyGems | Versão resolvida de cada gem |
| `packages.lock.json` | NuGet | Versão resolvida de cada pacote |

`go.mod`, `go.sum`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, manifests Maven/Gradle, `Package.resolved`, `Podfile.lock`, `vcpkg.json`, `conan.lock` e `pubspec.lock` são reconhecidos como cobertura não disponível. O Mitnick não consulta OSV com uma versão que não consegue demonstrar como resolvida; por exemplo, uma versão em `go.mod` pode ser apenas requisito e `go.sum` pode conter versões fora do grafo selecionado.

O scan usa apenas resultados já armazenados. Para cada ecossistema, o relatório indica dependências sem cache, cache vencido (mais de 30 dias), falhas e manifestos reconhecidos sem adaptador. Cache vazio significa “não consultado”, não “sem vulnerabilidades”. Uma correspondência OSV confirma que o pacote/versão foi retornado pela fonte; não comprova reachability, uso em runtime ou impacto de implantação. Sem severidade da fonte, o finding usa `info` e explica que o risco é desconhecido.

## Proveniência, atualização e dados

O catálogo mantém nomes de fontes, IDs originais, aliases, datas, sinais, versões/status da sincronização e bytes brutos dos registros de advisory. O importador CWE guarda seus dados normalizados e a versão do XML. Aliases ambíguos podem apontar a mais de um advisory; a consulta mostra todos os registros em vez de escolher um arbitrariamente. Uma atualização incompleta mantém dados anteriores e informa o erro em `intel status`.

Os feeds podem conter material sujeito a termos e licenças próprios. O Mitnick faz consultas sob demanda, não redistribui um espelho geral desses feeds e mantém a revisão de licenças/termos como condição para publicação. O snapshot GitHub embutido tem atribuição registrada em [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). A revisão jurídica e de dados continua pendente.

O score EPSS, CVSS e presença no KEV são sinais diferentes. O finding preserva fonte e data de cada sinal. A prioridade `urgent-review` atualmente é atribuída quando há sinal KEV; EPSS e CVSS são exibidos sem serem combinados em um score próprio. O Mitnick não mede reachability nem exposição de runtime.
