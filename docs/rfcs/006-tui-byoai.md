# RFC-006 — TUI e clientes CLI de IA

**Estado:** implementada; substitui o desenho de provedores HTTP configuráveis da RFC-004. **Data:** 2026-10-26.

## Fluxo

- A TUI permanece navegável por teclado. Na tela **AI Integrations**, setas/`j`/`k` escolhem Codex CLI ou Claude Code; `Enter` verifica a autenticação local existente e salva a seleção. `d` atualiza a lista pelo `PATH`; `t` faz uma chamada sem conteúdo de projeto e pode consumir créditos.
- `mitnick ai detect/list` só consulta o `PATH`; não inicia processos nem acessa rede. `mitnick ai connect codex|claude` verifica o login mantido pelo CLI e salva um perfil privado v2 com somente `provider`.
- Revisão assistida continua desabilitada por padrão. Na TUI, `a` ativa IA e `r` autoriza uma única análise; na CLI, use `scan --ai --ai-consent`. O consentimento é requerido para qualquer rota controlada pelo CLI.
- Erro na revisão mantém os findings determinísticos e registra cobertura incompleta. Respostas do modelo são consultivas, vinculadas a findings fornecidos e validadas pelo schema estrito.

## Restrições de execução

- Codex roda com `codex exec`, prompt em stdin, `--ephemeral`, `--ignore-user-config`, `--ignore-rules`, sandbox `read-only`, aprovação `never`, diretório temporário e flags de configuração para desabilitar shell, busca, apps, plugins, MCP, hooks e subagentes. Não há fallback se uma opção não for suportada.
- Claude Code precisa de versão 2.1.248 ou posterior. A execução usa `--restricted`, `--safe-mode`, `--tools ""`, bloqueio MCP, `--no-session-persistence`, `--permission-mode plan`, saída JSON e um turno.
- Nenhum caminho do projeto é passado como diretório de trabalho ao CLI. O prompt contém contexto limitado e sanitizado, enviado por stdin. Saídas são limitadas, parseadas estritamente e nunca aplicadas.
- `ai test` envia somente uma instrução fixa sem código, mas pode consumir créditos. O limite de gasto depende da conta/organização e não é estimado pelo Mitnick.
- Credenciais e sessões continuam sob controle do Codex/Claude e não são armazenadas pelo Mitnick. A rota e as políticas gerenciadas do CLI não são verificadas.

## Entregue

- TUI por teclado com seleção real entre os dois CLIs encontrados e comandos de conectar/testar.
- CLI `ai detect`, `list`, `connect` e `test`; flags de endpoint, modelo, token e tarifas removidas.
- Perfil v2 privado que guarda somente o ID do cliente. Perfis v1 de endpoint/modelo precisam ser recriados com `ai connect`.
- Permissão de conteúdo solicitada em cada scan e metadados do relatório sem endpoint/modelo/segredo.
- Testes usam executáveis simulados; nenhum login, conta real ou serviço de modelo foi chamado na suíte.

## Limitações a verificar antes de release

- Testar versões atuais do Codex e Claude Code em Linux, macOS e Windows, usando contas de teste e confirmando os modos restritos.
- Configurações centralizadas do CLI podem controlar execução, rede, autenticação e retenção. O Mitnick não consegue auditar ou substituir essas políticas.
- A redaction conhece padrões comuns e não garante remoção de todos os dados sensíveis. O consentimento por scan permanece obrigatório.
- Limites rígidos de uso e custo devem ser definidos no cliente/conta do usuário; não há estimativa local de cobrança.
