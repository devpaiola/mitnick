# ADR-003 — Não executar engines escolhidas pelo repositório

**Status:** aceita para v0.1.0-dev. **Data:** 2026-10-25.

## Decisão

Scans padrão não iniciam scripts, ferramentas MCP ou executáveis externos. O opt-in `mitnick scan --gitleaks` pode iniciar somente o executável `gitleaks` resolvido do `PATH`, depois de confirmar que ele está fora da raiz analisada. O scanner recebe uma cópia temporária dos arquivos descobertos; em Linux/macOS, o diretório e os arquivos usam modos `0700`/`0600`, enquanto no Windows herdam a ACL do diretório temporário, que deve ser privado. A integração exclui `.gitleaks.toml` da raiz para impedir que o repositório escolha a configuração da engine, usa `--no-git` e `--redact`, limpa variáveis de ambiente e limita execução/relatório. A cópia é removida em encerramento normal; não há apagamento físico garantido e um encerramento abrupto pode deixá-la no diretório temporário. `doctor` apenas detecta Gitleaks e OSV-Scanner; não os executa.

## Motivo

O conteúdo analisado é não confiável; descoberta de um binário não autentica sua origem nem seus argumentos. A execução fica desativada por padrão e exige decisão explícita. Mesmo com cópia temporária e ambiente reduzido, o binário opt-in ainda executa com os privilégios do usuário; o Mitnick não fornece sandbox de sistema operacional e o operador precisa confiar na instalação.

## Consequências

Gitleaks 8.16.0 tem integração opt-in testada; a execução usa só arquivos descobertos, limite de 30 segundos, relatório de até 16 MiB e erros sem saída bruta. A interface CLI e o formato JSON são conferidos por regressões e teste local. O OSV-Scanner permanece apenas detectado. Nenhuma engine é baixada, selecionada por configuração do repositório ou executada no scan padrão. A integração ainda requer revisão independente de proveniência e isolamento antes de release.
