# Snapshot local de advisories npm

**Revisado em:** 2026-10-25  
**Fonte:** GitHub Advisory Database, advisories revisadas pelos mantenedores.  
**Dados embutidos:** `internal/code/advisories.json`.

Este inventário descreve somente o snapshot npm distribuído dentro do scanner. O catálogo SQLite opcional consulta OSV para outros ecossistemas por `mitnick intel update` e é usado offline durante o scan; veja [fontes e cobertura](data-sources.md).

O scanner lê `package-lock.json` e `npm-shrinkwrap.json` sem rede. As faixas são intervalos de semver com início inclusivo e versão corrigida exclusiva. Uma advisory que cobre várias linhas de versão tem uma entrada por faixa.

Esta revisão contém 37 intervalos, 15 advisories distintas e 7 nomes de pacote npm.

| Pacote | Advisory | Faixas afetadas → corrigida |
| --- | --- | --- |
| lodash | [GHSA-xxjr-mmjv-4gpg](https://github.com/advisories/GHSA-xxjr-mmjv-4gpg) | `>=4.0.0 <4.17.23` |
| lodash | [GHSA-f23m-r3pf-42rh](https://github.com/advisories/GHSA-f23m-r3pf-42rh) | `>=4.17.23 <4.18.0` |
| lodash | [GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) | `>=4.0.0 <4.18.0` |
| axios | [GHSA-pf86-5x62-jrwf](https://github.com/advisories/GHSA-pf86-5x62-jrwf) | `>=0.0.0 <0.31.1`; `>=1.0.0 <1.15.1` |
| axios | [GHSA-42h9-826w-cgv3](https://github.com/advisories/GHSA-42h9-826w-cgv3) | `>=0.28.0 <0.33.0`; `>=1.0.0 <1.18.0` |
| axios | [GHSA-gcfj-64vw-6mp9](https://github.com/advisories/GHSA-gcfj-64vw-6mp9) | `>=0.31.1 <0.33.0`; `>=1.15.2 <1.18.0` |
| axios | [GHSA-3pq3-5fj3-cg6v](https://github.com/advisories/GHSA-3pq3-5fj3-cg6v) | `>=1.13.0 <1.20.0` |
| axios | [GHSA-m8m8-qj5v-23w3](https://github.com/advisories/GHSA-m8m8-qj5v-23w3) | `>=1.15.2 <1.20.0` |
| axios | [GHSA-r4gj-5m52-g5wh](https://github.com/advisories/GHSA-r4gj-5m52-g5wh) | `>=1.17.0 <1.20.0` |
| axios | [GHSA-x97p-jq2g-jp4f](https://github.com/advisories/GHSA-x97p-jq2g-jp4f) | `>=0.28.0 <0.34.0`; `>=1.15.1 <1.20.0` |
| next | [GHSA-mcj8-r9mp-w47p](https://github.com/advisories/GHSA-mcj8-r9mp-w47p) | `>=15.0.0 <15.5.27`; `>=16.0.0 <16.3.8` |
| next | [GHSA-4jqv-mc3x-m676](https://github.com/advisories/GHSA-4jqv-mc3x-m676) | `>=15.0.0 <15.5.27`; `>=16.0.0 <16.3.8` |
| react-server-dom-parcel | [GHSA-fv66-9v8q-g76r](https://github.com/advisories/GHSA-fv66-9v8q-g76r) | `>=19.0.0 <19.0.1`; `>=19.1.0 <19.1.2`; `>=19.2.0 <19.2.1` |
| react-server-dom-turbopack | [GHSA-fv66-9v8q-g76r](https://github.com/advisories/GHSA-fv66-9v8q-g76r) | `>=19.0.0 <19.0.1`; `>=19.1.0 <19.1.2`; `>=19.2.0 <19.2.1` |
| react-server-dom-webpack | [GHSA-fv66-9v8q-g76r](https://github.com/advisories/GHSA-fv66-9v8q-g76r) | `>=19.0.0 <19.0.1`; `>=19.1.0 <19.1.2`; `>=19.2.0 <19.2.1` |
| react-server-dom-parcel | [GHSA-wx67-qw84-cm4g](https://github.com/advisories/GHSA-wx67-qw84-cm4g) | `>=19.1.0 <19.1.9`; `>=19.2.0 <19.2.8` |
| react-server-dom-turbopack | [GHSA-wx67-qw84-cm4g](https://github.com/advisories/GHSA-wx67-qw84-cm4g) | `>=19.0.0 <19.0.8`; `>=19.1.0 <19.1.9`; `>=19.2.0 <19.2.8` |
| react-server-dom-webpack | [GHSA-wx67-qw84-cm4g](https://github.com/advisories/GHSA-wx67-qw84-cm4g) | `>=19.0.0 <19.0.8`; `>=19.1.0 <19.1.9`; `>=19.2.0 <19.2.8` |
| minimist | [GHSA-xvch-5gv4-984h](https://github.com/advisories/GHSA-xvch-5gv4-984h) | `>=0.0.0 <0.2.4`; `>=1.0.0 <1.2.6` |

## Limites

- Isto é uma seleção pequena de advisories npm, não um feed completo. Nenhuma consulta ou atualização de rede ocorre durante o scan.
- Uma versão afetada pode exigir uso de determinada API, adapter, router, deployment ou condição de processo descrita na advisory. O scanner compara apenas nome e versão do pacote; não confirma reachability nem essas condições de execução.
- A detecção cobre os pacotes presentes nos lockfiles npm analisados, inclusive dependências aninhadas descritas neles. Não lê os lockfiles de outros ecossistemas.
- A data acima registra revisão manual do snapshot; releases futuras devem repetir a conferência nas fontes, atualizar esta tabela e o changelog, adicionar testes positivos e negativos e executar a suíte.
