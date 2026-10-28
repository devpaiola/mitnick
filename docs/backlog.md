# Backlog inicial

Itens que faltam para considerar concluídos os marcos de lançamento descritos em [`scope/escopo-v1.md`](../scope/escopo-v1.md):

| Prioridade | Trabalho | Evidência de saída |
| --- | --- | --- |
| P0 | Ampliar cobertura de advisories e adapters SCA com política explícita de rede/offline. | Catálogo SQLite e integração direta com OSV já consultam versões resolvidas por `intel update`; o scan permanece offline. Snapshot npm, adaptadores e cache seguem limitados. O executável OSV-Scanner externo não está integrado. |
| P0 | Aumentar cobertura de JS/TS, Next.js, Supabase e clientes MCP suportados. | Matriz versionada de regras, fixtures, taxa de falso positivo e revisão de segurança. |
| P0 | Validar esquema SARIF com consumidor GitHub e semântica de bloqueio/erro parcial na Action. | Workflow em pull request, upload SARIF e evidência passa/falha nos thresholds. |
| P0 | Completar threat review de filesystem concorrente, resource limits e integração de clientes CLI. | Revisão independente, validação de modos restritos Codex/Claude em versões reais, correções e regressões. |
| P0 | Testar builds Linux/macOS/Windows e arquiteturas escolhidas. | Matriz CI verde em versões Go oficialmente mantidas. |
| P0 | Concluir revisão de licença, clearance do nome, canal SECURITY e publicação dos artefatos de release. | Decisões registradas, busca de marca em classes/mercados relevantes, SBOM e checksums revisados, assinatura decidida e processo de publicação aprovado. |
| P1 | Validar compatibilidade dos adaptadores com versões correntes de Codex CLI e Claude Code. | Execução manual com contas de teste em matriz documentada; respostas permanecem observações consultivas estritas, sem campos de correção ou patch. |
| P1 | Configuração de suppressions por policy file e expiração/auditoria de exceções. | Schema revisado e fixtures de policy. |
| P1 | Adicionar benchmarks em projetos reais e ampliar os mapeamentos CWE/OWASP no JSON/SARIF. | Baselines reproduzíveis e limites publicados; a RFC-005 já implementa metadados iniciais. |

Este backlog não altera o escopo: o estado atual é uma primeira fatia executável, não uma release pública `v0.1.0` concluída.
