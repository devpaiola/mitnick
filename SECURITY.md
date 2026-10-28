# Política de segurança

## Reportar uma vulnerabilidade

Esta cópia local ainda não tem repositório remoto nem canal privado de reporte configurado. Não abra issue pública com detalhes de uma vulnerabilidade ainda não corrigida. Antes de qualquer publicação, os mantenedores precisam configurar um canal privado, testar quem pode acessá-lo e atualizar esta seção com as instruções verificadas. Não envie código confidencial ou credenciais em tickets públicos.

## Limites de segurança do Mitnick

- O scan não executa o projeto analisado nem comandos declarados em arquivos MCP/agente.
- Symlinks encontrados dentro da árvore são ignorados; há limites de tamanho de arquivo, total e quantidade.
- Sem `--ai`, nenhum CLI de IA é iniciado. `--ai --ai-consent` encaminha contexto sanitizado ao Codex CLI ou Claude Code escolhido; conta, destino e cobrança seguem as configurações do cliente. O Mitnick desativa ferramentas do modelo, mas o CLI executa com a identidade do usuário e deve ser instalado de uma fonte confiável.
- As evidências de credenciais são mascaradas. Reports podem conter paths locais e descrições de regras; trate-os como dados do repositório.
- As regras e advisories são incompletas. Resultado limpo não prova que o projeto é seguro.

## Escopo

Relatos são bem-vindos sobre execução não intencional de conteúdo analisado, saída de segredos, bypass de limites de filesystem, sucesso falso em erro de engine, falhas de redaction ou comportamento de rede sem opt-in.
