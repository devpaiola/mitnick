# SQL Injection em Python (CWE-89)

O exemplo vulnerável concatena uma entrada em SQL. O exemplo corrigido usa
parâmetro vinculado pelo driver; substitua `?` se o driver exigir outro
placeholder. O teste é uma verificação estática do exemplo seguro.
Execute a partir deste diretório com `python3 test.py`; ele não importa nem
executa os exemplos vulnerável ou corrigido.

Estes arquivos são dados de demonstração. O Mitnick os exibe, mas nunca os
executa durante um scan ou ao sincronizar o catálogo.

Referências:

- <https://cwe.mitre.org/data/definitions/89.html>
- <https://owasp.org/www-project-cheat-sheets/cheatsheets/Query_Parameterization_Cheat_Sheet.html>
