# RFC-003 — Política e supressões

**Status:** aceito para v0.1.0-dev. **Data:** 2026-10-25.

`fail_on` aceita `critical`, `high`, `medium`, `low`, `info` ou `none`; o padrão é `high`. Severidades iguais ou acima do threshold retornam código 1. Erro de descoberta, scanner ou provedor habilitado retorna código 2. Conclusão sem achado no threshold retorna 0. Nenhum erro de scanner pode virar sucesso silencioso.

Supressões locais usam comentário real da sintaxe do arquivo, inline, `mitnick:ignore RULE_ID -- motivo`. O ID precisa coincidir exatamente e a justificativa após `--` não pode estar vazia; texto dentro de string não suprime. O achado fica no relatório marcado `suppressed` e gera `POLICY-SUPPRESSION`. Exclusões `.mitnickignore` controlam arquivos lidos, não reduzem threshold nem removem achados existentes.
