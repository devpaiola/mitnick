# Contribuindo

Obrigado por contribuir com Mitnick. Antes de abrir uma mudança:

1. Abra uma issue para mudanças de escopo, regras novas ou alterações de schema.
2. Para regras, documente a ameaça, o limite da regra, recomendação, pelo menos um caso positivo e um negativo.
3. Preserve o scan passivo, o mascaramento de evidências e a opt-in explícita para rede/IA.
4. Use Go format, erros explícitos, `context.Context` em operações que podem demorar e não registre tokens ou conteúdo bruto.
5. Execute `go test ./...` e `go vet ./...` localmente antes de enviar a alteração.

O código e os arquivos analisados são entrada não confiável. Não execute comandos encontrados em repositórios examinados. Engines externas precisam de justificativa, limites, timeout, versão documentada e modo de falha que não resulte em sucesso falso.

Dependências de GitHub Actions devem usar o SHA completo do commit upstream, com a versão de release em comentário. Ao atualizar um pin, confira a tag e os metadados da action upstream e mantenha uma revisão do diff.

## Convenções

- Go: nomes claros, interfaces pequenas e dependências mínimas.
- Finding: regra estável, origem rastreável, evidência sanitizada, confiança/estado honestos e recomendação acionável.
- Configuração: versionada, validada e sem credenciais em texto puro.
- Documentação inicial em português; nomes de API e identificadores de regra em inglês.
- Mudanças incompatíveis no JSON exigem nova versão de schema e nota no changelog.

Ao contribuir, você concorda em seguir o [Código de Conduta](CODE_OF_CONDUCT.md). Licenças de código, fixtures e regras devem ser compatíveis com a licença do projeto e ter origem registrada.
