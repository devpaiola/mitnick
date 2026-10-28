# Regras e cobertura

Mitnick inclui uma pequena matriz inicial. Ela é um ponto de partida, não uma declaração de cobertura completa. `mitnick rules list` mostra o inventário compilado.

| IDs | Domínio | Evidência | Estado padrão | Limitação |
| --- | --- | --- | --- | --- |
| SEC001–SEC005 | code | Token/chave ou atribuição de credencial; sempre mascarada | suspected | Padrões e heurísticas podem perder formatos ou sinalizar exemplos. |
| GITLEAKS-* | code | Padrões de segredo encontrados por Gitleaks 8.16.0, quando `--gitleaks` é usado | suspected | Binário externo executado com opt-in e privilégios do usuário; não valida se a credencial está ativa. |
| WEB001 | code | Uso de `dangerouslySetInnerHTML` | suspected | Não acompanha sanitização no fluxo de dados. |
| WEB002 | code | `eval` ou `new Function` | suspected | Não modela origem/controlabilidade da entrada. |
| WEB003 | code | CORS `*` | suspected | Pode ser intencional para conteúdo público. |
| WEB004 | code | `rejectUnauthorized: false` | suspected | Identifica apenas padrão textual. |
| SUP001 | code | Nome de variável pública contém chave `service_role` ou `secret_key` do Supabase | suspected | A heurística não analisa configuração efetiva; a chave `publishable` é permitida no cliente. |
| SUP002 | code | Migration Supabase desativa RLS | suspected | Detecção textual; não acompanha alterações subsequentes nem grants. |
| SUP003 | code | Policy Supabase usa `USING/WITH CHECK (true)` | suspected | Pode ser intencional para dados públicos; revise roles e grants. |
| SUP004 | code | Edge Function tem `verify_jwt = false` | suspected | Não verifica camada alternativa de autenticação. |
| GHSA-* | code | Versão instalada de lodash, axios, next, React Server Components ou minimist em intervalo afetado via lock npm | validated | Snapshot limitado; não verifica reachability, condição de runtime, nem consulta advisories atuais automaticamente. |
| SCA-OSV-* | dependency | OSV retornou advisory para pacote/ecossistema/versão exatos consultados anteriormente | validated | Requer cache atualizado via `intel update`; não avalia reachability ou uso em runtime. Sinais CVSS, EPSS e KEV mantêm fonte e data próprias. |
| AGENT001 | agent | Texto em inglês ou português aparenta autorizar execução autônoma | suspected | Não interpreta o modelo de permissões de cada cliente. |
| MCP001 | agent | Shell, download-and-run ou package runner não fixado em config MCP | suspected | Revisão estática; não executa nem valida o servidor. |
| MCP002 | agent | Configuração aparenta dar acesso a raiz/home | suspected | Padrões heurísticos; revise o escopo real do servidor. |

`SUP001` segue a distinção documentada pelo [Supabase](https://supabase.com/docs/guides/getting-started/api-keys) (consultado em 25/10/2026): chaves `publishable` podem ir ao cliente; `secret` e a antiga `service_role` são para componentes de backend. A regra verifica somente nomes de variáveis com prefixo público (`NEXT_PUBLIC_` ou `VITE_`), sem examinar qual chave está configurada.

## Supressões

Uma supressão válida precisa incluir o ID exato e uma justificativa na mesma linha, dentro de um comentário reconhecido para a extensão do arquivo:

```js
const html = renderTrustedTemplate(input); // mitnick:ignore WEB001 -- renderTrustedTemplate sanitiza com allowlist
```

O achado continua no relatório com `suppressed: true`; a regra `POLICY-SUPPRESSION` registra a existência da exceção. Supressões não mudam a evidência original e não são lidas de arquivos externos ao scan.

O marcador precisa estar no comentário, não em uma string ou texto de configuração. A justificativa começa com `--`; comentários sem motivo ou com outro ID não alteram o threshold.

## Banco de advisories

O snapshot está em `internal/code/advisories.json`; cada entrada registra ecossistema, pacote, um intervalo de versão, correção e URL da advisory. Advisories com várias linhas de versão têm uma entrada por intervalo. Atualizações exigem revisão da fonte, positivo/negativo de fixture, data de revisão no changelog e execução da suíte. Consulte [data, escopo e fontes do snapshot](advisory-snapshot.md). O snapshot embutido não substitui um feed completo de vulnerabilidades. Não há atualização nem consulta de rede automática.

O catálogo local com OSV, CWE, KEV, CVE List, NVD, GitHub Advisory e EPSS é separado do snapshot npm compilado. O scan só usa o cache; sincronização, suporte por lockfile e indicação de dados ausentes estão descritos em [fontes e cobertura](data-sources.md).
