# Baseline de desempenho local

Medição local em 2026-10-25. Os fixtures usam `go test ./internal/core -run='^$' -bench='^BenchmarkScanFixtures$' -benchmem -count=3`; a medição do repositório usa `go test ./internal/core -run='^$' -bench='^BenchmarkScanRepository$' -benchmem -count=5`.

Ambiente: Go 1.26.8, Linux `amd64`, Intel Core i7-1165G7 @ 2.80 GHz. Cada caso percorre o alvo inteiro, executando discovery e os scanners de código/agentes.

| Alvo | Arquivos | Mediana | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| `testdata/secure` | 5 | 743 µs/op | 70,270 | 957 |
| `testdata/vulnerable` | 8 | 1.099 ms/op | 164,943 | 1,753 |
| Checkout Mitnick (worktree medido) | 72 | 92.994 ms/op | 2,524,425 | 5,293 |

As métricas são medianas de 3 execuções dos fixtures e 5 do checkout. O self-scan do Mitnick produziu 13 findings e nenhum erro de engine no worktree medido. Os fixtures pequenos validam a medição repetível e o self-scan dá um ponto de referência de repositório; nenhum deles representa projetos Next.js ou Supabase de produção nem define metas de performance. Benchmarks em projetos externos de referência continuam pendentes.
