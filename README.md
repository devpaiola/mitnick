# Mitnick

Mitnick é uma ferramenta local-first em Go para procurar riscos comuns em aplicações JavaScript/TypeScript e configurações de agentes/MCP. Em terminal interativo, `mitnick` abre a TUI; o scan padrão é passivo: não inicia o projeto, não executa comandos declarados nos arquivos, não inicia engines externas e não acessa a rede.

> Versão inicial `0.1.0`. O conjunto de regras e a base local de advisories são limitados; este projeto não promete ausência de vulnerabilidades nem substitui uma auditoria especializada.

O Mitnick é open source e opera localmente. Scans, inteligência e relatórios não dependem de conta ou serviço Cloud.

## Instalação e primeiro scan

Em Linux ou macOS, instale a versão mais recente publicada pelo GitHub:

```sh
curl -fsSL https://raw.githubusercontent.com/devpaiola/mitnick/main/scripts/install.sh -o install-mitnick.sh
sh install-mitnick.sh
rm install-mitnick.sh
```

No Windows 10 ou mais recente, abra o PowerShell:

```powershell
$installer = "$env:TEMP\install-mitnick.ps1"
Invoke-WebRequest https://raw.githubusercontent.com/devpaiola/mitnick/main/scripts/install.ps1 -OutFile $installer
& $installer
Remove-Item $installer
```

Os instaladores identificam o sistema e a arquitetura, baixam o pacote da GitHub Release, verificam `SHA256SUMS` e instalam sem privilégios de administrador. Linux/macOS instalam em `~/.local/bin`; se o script precisar ajustar o `PATH`, abra um novo terminal ao terminar. Windows instala em `%LOCALAPPDATA%\Programs\Mitnick` e adiciona esse diretório ao `PATH` do usuário. Para escolher outro diretório no Linux/macOS, defina `MITNICK_INSTALL_DIR`; no PowerShell, use `-InstallDir`.

Depois, os comandos ficam disponíveis diretamente:

```sh
mitnick scan .
mitnick scan . --gitleaks
mitnick menu
mitnick config init
mitnick scan . --format json --output ../mitnick-report.json
mitnick scan . --format sarif --output ../mitnick.sarif
```

Para compilar a partir do código-fonte, requer Go 1.26 ou mais recente:

```sh
go build -o mitnick ./cmd/mitnick
```

O scan termina com código `0` se não houver achados no threshold, `1` se houver achados no threshold, `2` para erro de configuração/argumento, `3` para falha operacional ou cobertura incompleta e `130` quando interrompido. O threshold padrão é `high`; ajuste com `--fail-on critical|high|medium|low|info|none` ou no arquivo de configuração. Sem terminal interativo, `mitnick` sem argumentos exibe ajuda e termina; `mitnick menu` exige terminal.

## Comandos

- `mitnick scan [diretório]`: verifica código, lockfiles npm, instruções de agentes e configurações MCP.
- `mitnick menu`: TUI por teclado para scan, findings, integrações BYOAI, inteligência, exportação, privacidade e diagnósticos.
- `mitnick scan [diretório] --gitleaks`: opt-in para executar o Gitleaks instalado nos arquivos já descobertos pelo Mitnick.
- `mitnick doctor`: verifica configuração e engines sem chamadas de rede; `--ai-check` envia um pedido de teste sem conteúdo do projeto e pode consumir créditos.
- `mitnick ai detect` / `list`: lista Codex CLI e Claude Code encontrados no `PATH`, sem iniciá-los.
- `mitnick ai connect codex|claude`: verifica o login já existente no CLI escolhido e salva somente qual cliente usar. O login continua sob controle do cliente.
- `mitnick ai test`: faz um pedido mínimo ao CLI selecionado, sem código do projeto; pode consumir créditos da conta.
- `mitnick config init [arquivo]` / `validate [arquivo]`: cria ou valida configuração JSON.
- `mitnick rules list`: lista as regras compiladas.
- `mitnick intel update [diretório]`: atualiza o catálogo local (CWE e CISA KEV; OSV para dependências com versão resolvida no diretório). Fontes CVE List, NVD, GitHub Advisory e EPSS podem ser consultadas por ID.
- `mitnick intel status` / `mitnick intel show <ID>`: consulta fontes e advisories do catálogo local, sem rede.
- `mitnick explain CWE-89 --lang python`: mostra fraqueza, mapeamento OWASP e exemplo local sem executar os arquivos.
- `mitnick report report.json --format sarif`: renderiza um relatório JSON existente.
- `mitnick version`: mostra versão e plataforma.

Consulte `mitnick scan --help` para as flags. As exclusões podem ser passadas por `--exclude` ou `.mitnickignore`; são aceitos até 128 padrões de até 256 bytes, com validação de glob. Os diretórios `.git`, `node_modules`, `vendor`, `dist`, `build`, `.next` e `coverage` são ignorados por padrão. Arquivos acima de 2 MiB, binários e symlinks são ignorados. O scan limita a leitura a 50 mil arquivos, 100 mil entradas e 256 MiB.

O timeout padrão de 30 segundos cobre descoberta, scanners e a revisão opcional por IA; `--timeout` pode estendê-lo até 1 hora. Gitleaks tem também um limite próprio de 30 segundos. `Ctrl-C` e `SIGTERM` cancelam o trabalho. Relatórios precisam ficar fora do diretório analisado, são criados com modo `0600` em Linux/macOS e nunca sobrescrevem um destino existente. No Windows, o arquivo herda a ACL do diretório de destino; escolha um diretório privado.

`mitnick report` lê somente relatórios JSON regulares de até 64 MiB.

## Abrir a TUI e executar um scan

Compile o programa e abra o menu em um terminal interativo:

```sh
go build -o mitnick ./cmd/mitnick
./mitnick menu
```

Use as setas para escolher uma tela e `Enter` para abrir. Primeiro autentique o CLI que quer usar:

```sh
codex login
# ou
claude auth login
```

Na tela **AI Integrations**, use `↑`/`↓` (ou `1` para Codex, `2` para Claude) para selecionar um CLI e `Enter` para verificar o login já existente. Enter não abre um chat nem inicia um scan; o Mitnick guarda apenas a seleção. Para enviar um teste sem código, pressione `t`; para usar a IA no scan, volte com `Esc`, abra **Scan Project** e pressione `a`, `r` e `Enter`. O cliente define conta, modelo e destino do pedido.

Também é possível conectar pela CLI:

```sh
./mitnick ai detect
./mitnick ai connect codex   # ou: claude
./mitnick ai test            # pedido sem código; pode consumir créditos
```

Para fazer uma análise assistida, abra **Scan Project**, pressione `a` para habilitar a IA, `r` para autorizar o envio uma vez e `Enter` para iniciar. Sem `a`, o scan continua local e determinístico. A autorização vale para um scan e é exigida mesmo quando o destino é gerenciado pelo CLI.

```sh
./mitnick scan . --ai --ai-consent
```

O teste envia somente uma instrução fixa e não lê arquivos do projeto. A análise envia IDs, fingerprints, enums, listas permitidas de CWE/referências e até cinco linhas ao redor de findings de código. O contexto fonte fica limitado a 16 KiB, entram até 20 findings, o pedido a 40 KiB e a resposta a 1 MiB. Caminhos, títulos, evidências livres, instruções/configurações de agentes e metadados de pacotes são omitidos; padrões conhecidos de segredo são mascarados e arquivos com findings `SEC-*` ou origem Gitleaks não fornecem contexto. A cobertura da redaction é limitada, por isso leia e revise o código antes de consentir.

O Mitnick desativa ferramentas de shell, busca, plugins, MCP e subagentes no Codex; no Claude Code, exige modo restrito, desativa ferramentas internas e bloqueia ferramentas MCP. Ambos recebem o contexto por stdin, rodam fora do diretório analisado e retornam somente observações JSON validadas. Respostas não são executadas nem aplicadas. O Mitnick não controla o modelo, a conta, o roteamento corporativo ou a cobrança definidos pelo CLI. Cada scan com IA exige `--ai-consent`; não há estimativa de custo, então use os limites de uso da sua conta/organização.

No Linux, o Codex também precisa iniciar seu sandbox Bubblewrap. Na versão instalada, verifique sem enviar um prompt ao modelo com `codex sandbox /usr/bin/true`. `codex doctor` verifica também a conectividade do provedor sem analisar o projeto. Se o teste do sandbox falhar, corrija a configuração do sandbox/namespace ou do diretório privado `~/.codex/app-server-control`; o Mitnick não desativa o isolamento para contornar a falha.

## Configuração

`mitnick config init` cria `mitnick.json` com permissões restritas. Valores de flags prevalecem sobre variáveis de ambiente, que prevalecem sobre o arquivo:

```json
{
  "version": 1,
  "workers": 4,
  "timeout_seconds": 30,
  "fail_on": "high",
  "exclude": ["fixtures/known-vulnerable/**"],
  "exclude_dirs": ["generated"]
}
```

Variáveis disponíveis: `MITNICK_FAIL_ON`, `MITNICK_WORKERS` e `MITNICK_TIMEOUT_SECONDS`. `mitnick ai connect` grava apenas o ID do CLI selecionado em `mitnick/ai.json`, no diretório de configuração do usuário, com permissão `0600`. Tokens e sessão de autenticação não são lidos nem gravados pelo Mitnick.

## Análise assistida opcional

Sem `--ai`, nenhum cliente de modelo é iniciado. Para análise, conecte um CLI autenticado e passe `--ai --ai-consent`; o modelo e a conta são os que o Codex ou Claude Code já usa.

## Cobertura e limitações conhecidas

O Mitnick não inspeciona a conta, o modelo, o endpoint nem a configuração corporativa do CLI. Verifique as configurações de rede e privacidade do Codex/Claude antes de enviar contexto.

- Segredos: padrões iniciais para chaves AWS, tokens GitHub/Slack, chaves privadas e atribuições genéricas de credenciais. Valores são substituídos por `[REDACTED]` na evidência.
- Código: padrões prioritários de HTML inseguro, avaliação dinâmica, CORS wildcard, TLS desabilitado e variável pública de service key Supabase.
- Segredos: regras internas e Gitleaks 8.16.0 testado localmente; `--gitleaks` é explícito, não usa rede, recebe cópia temporária dos arquivos descobertos, redige os valores no relatório e tem limite de tempo/saída. Em Linux/macOS, diretório e arquivos temporários usam modos `0700`/`0600`; no Windows, herdam a ACL do diretório temporário, que deve ser privado. A cópia é removida no encerramento normal; não há garantia de apagamento físico e um encerramento abrupto pode deixá-la no diretório temporário. O processo externo ainda executa com a conta do usuário e não é um sandbox de sistema operacional; use apenas um binário confiável. `doctor` só detecta engines e nunca as executa.
- Dependências: leitura de lockfiles de npm, Cargo, Composer, Bundler e NuGet, além de `requirements.txt` com versões pinadas. OSV é consultado somente por `intel update` e o scan usa esse cache offline; as advisories embutidas de npm são um snapshot pequeno separado. Go e outros manifests sem adapter aparecem como cobertura não disponível. Nenhuma correspondência avalia reachability ou uso em runtime. Veja [fontes e limites](docs/data-sources.md) e [o snapshot npm](docs/advisory-snapshot.md). O executável OSV-Scanner externo é detectado por `doctor`, mas não é integrado.
- Agentes: inspeção de alguns nomes comuns de arquivos de instrução e configuração MCP para comandos de shell/package runner e escopos amplos de filesystem. É análise heurística e não valida a semântica de cada cliente.
- Supabase: verifica nomes de chaves legadas `service_role` ou novas `secret_key` em variáveis públicas, migrations que desabilitam RLS ou aceitam qualquer linha e Edge Functions com validação JWT desativada. São padrões estáticos suspeitos; não avaliam RLS, grants ou autenticação em runtime.
- BYOAI: Codex CLI e Claude Code autenticados pelo próprio usuário. O Mitnick usa modos não interativos sem ferramentas e envia somente contexto sanitizado após consentimento por scan; modelo, destino e custo dependem da configuração e conta do CLI.
- SOs: o workflow CI declara teste e build em Linux, macOS e Windows `amd64` com Go 1.26 e 1.27; essa matriz precisa passar antes de uma release. `scripts/package-release.sh` gera pacotes locais, checksums e SBOM; o workflow por tag prepara release pública e atestação SLSA, mas ainda não foi executado e não há artefatos publicados ou atestados.

Findings de regras heurísticas têm estado `suspected`; advisories embutidas têm estado `validated`, referenciando a fonte. Um achado pode ser silenciado somente com comentário inline real contendo justificativa, por exemplo `// mitnick:ignore WEB002 -- template sanitizado por componente X`; o marcador dentro de uma string não é aceito. A supressão permanece no relatório como informação auditável.

## Desenvolvimento

```sh
go test ./...
go build ./cmd/mitnick
```

Veja [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [regras](docs/rules.md), o [checklist de release](docs/release-readiness.md), os [RFCs](docs/rfcs/) e os [ADRs](docs/adr/).
O [baseline de desempenho](docs/performance-baseline.md) registra medições dos fixtures e do self-scan do Mitnick; benchmarks em projetos externos de referência continuam pendentes.

## Licença e nome

Distribuição proposta sob Apache-2.0; veja o [inventário de licenças de terceiros](THIRD_PARTY_NOTICES.md). A revisão jurídica de compatibilidade e a análise de marca do nome ainda precisam ocorrer antes de publicação ([status da busca](docs/name-check.md)). Veja também [LICENSE](LICENSE).
