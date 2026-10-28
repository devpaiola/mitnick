# Changelog

## Unreleased — 0.1.0-dev

- Integrações de IA agora detectam e conectam o Codex CLI ou Claude Code autenticado pelo usuário; seleção de endpoint, modelo, API key e tarifas removida. A análise exige consentimento por scan e usa o modelo/conta do CLI selecionado.
- Chamadas de revisão usam modos sem ferramentas, contexto via stdin, diretório temporário e parsing JSON estrito; o teste de conexão envia apenas uma instrução fixa, sem conteúdo do projeto.
- Fundação da CLI Go, configuração JSON, discovery passivo e findings schema v1.
- Scanners iniciais de segredos, padrões web, advisories npm embutidas e configurações de agente/MCP.
- Gitleaks 8.16.0 como engine opt-in sobre cópia temporária dos arquivos descobertos, com ambiente reduzido, timeout, relatório redigido e limites; scan padrão continua sem engines externas.
- Regras Supabase para RLS/policies/Edge Functions e detecção de autonomia de agentes em português.
- Regra SUP001 reconhece nomes públicos de novas Supabase secret keys e não sinaliza publishable keys.
- Discovery respeita cancelamento durante a caminhada, limita entradas e revalida o arquivo aberto; configuração exige objeto JSON versionado.
- CLI encerra com segurança em `Ctrl-C`/`SIGTERM`; o timeout total inclui revisão BYOAI, saídas de relatório verificam erros de sincronização/fechamento e rejeitam symlinks/dispositivos.
- Parsers rejeitam chaves JSON duplicadas em config, MCP, lockfiles npm e relatórios; lockfiles sem estrutura suportada falham explicitamente e comparações semver incluem identificadores numéricos maiores que `uint64`.
- Findings de dependências apontam à chave exata do pacote no lockfile npm, inclusive quando chaves compartilham prefixo, usam escapes JSON ou repetem versões em dependências legadas aninhadas.
- Leitura de configuração é limitada a 1 MiB e revalida o arquivo aberto; `mitnick report` limita a entrada a 64 MiB e exige arquivo regular.
- Exclusões de configuração e `.mitnickignore` validam sintaxe e limitam quantidade/tamanho para evitar custo desproporcional por arquivo.
- Supressões exigem comentário da sintaxe do arquivo, ID exato e justificativa `--`; marcadores dentro de strings não silenciam findings.
- Respostas BYOAI acima de 1 MiB falham explicitamente e truncamentos preservam limites UTF-8.
- Pedidos de revisão são limitados a 40 KiB e respostas a 1 MiB; o Mitnick não estima nem limita custos, que dependem da conta e das políticas do CLI.
- Contexto BYOAI mascara fine-grained GitHub tokens, atribuições `passwd` e chaves privadas truncadas; arquivos com findings de segredo não enviam contexto fonte.
- Matriz de fixtures cobre positivos e negativos para regras de segredo, web, Supabase, agentes e MCP.
- Fuzzing de lockfiles npm, JSON de configuração e arquivos de instruções/configuração de agentes.
- Saídas terminal, JSON e SARIF; política de threshold e supressões justificadas.
- Revisão por IA opt-in com contexto limitado a trechos de código mascarados e fingerprints para rastreabilidade; respostas consultivas não são executadas nem aplicadas.
- Snapshot de advisories npm ampliado para lodash, axios, next, React Server Components e minimist com intervalos revisados segundo GitHub Advisory Database; arquivos de configuração MCP Gemini/Copilot passam a ser reconhecidos.
- Empacotador reproduzível para Linux/macOS/Windows `amd64`, SBOM SPDX 2.3 e `SHA256SUMS`; CI declara Go 1.26 e 1.27.
- GitHub Actions upstream fixadas por SHA completo, com versões de release registradas nos comentários.
- Workflow de release por tag com verificação de checksums, atestação de proveniência e publicação de pacotes; tags com sufixo de pré-release são publicadas como pré-releases.
- Baseline de desempenho ampliada com um self-scan do repositório além dos fixtures.
- Action composta, exemplo de workflow, inventário de licenças de runtime e documentação de limitações.
- Catálogo SQLite offline com conectores OSV, CWE, CISA KEV, CVE List V5, NVD, GitHub Advisory e FIRST EPSS; `intel update/status/show` e `explain CWE-89`.
- SCA via cache OSV para npm, PyPI pinado, Cargo, Composer, RubyGems e NuGet, com cobertura ausente/stale/falha no relatório e metadados CWE/OWASP/CVSS/EPSS/KEV.
- Rule pack inicial e taxonomias OWASP curadas; exemplo Python de SQL injection exibido sem execução; fixtures de conectores e parsers.
- Avisos upstream completos de runtime do SQLite e licenças de dependências Go incluídos em `LICENSES/`.
- TUI Bubble Tea por teclado, menu automático em terminal interativo, ajuda em CI, filtros/detalhes de findings, status de inteligência e exportação privada fora do projeto.
- Comandos `ai detect/list/connect/test`; perfil privado armazena somente o CLI selecionado, sem credenciais, e a análise fica bloqueada sem consentimento explícito.
- Resposta de IA limitada a observações JSON vinculadas a findings/contexto; schema estrito rejeita patches, IDs e referências inventados; códigos de saída agora distinguem falha operacional (`3`) de erro de configuração (`2`) e cancelamento (`130`).
- Relatórios CLI e TUI recusam destinos dentro do projeto ou já existentes; teste snapshot confirma integridade byte a byte do alvo após scan.
