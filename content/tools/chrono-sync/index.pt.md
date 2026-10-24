---
title: "Conversor de Timestamp Unix (Epoch em Data)"
description: "Converta timestamps Unix em datas e datas em epoch, em UTC e no horário local. Segundos ou milissegundos detectados automaticamente. Relógio epoch ao vivo."
intro: "O **ChronoSync** converte **timestamps Unix (epoch)** em datas legíveis e vice-versa. Ele mostra o timestamp atual correndo ao vivo, aceita segundos ou milissegundos e entrega cada resultado em UTC e no seu fuso horário."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["conversor timestamp unix", "converter epoch", "timestamp para data", "data para timestamp", "epoch time agora", "unix time", "milissegundos para data", "conversor epoch"]
tags: ["ferramentas-dev", "tempo", "conversor", "ferramenta"]
app_category: "DeveloperApplication"
tool_file: "/tools/chrono-sync/"
tool_title: "ChronoSync, conversor de timestamps Unix"
tool_height: 700
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Veja o **Timestamp UNIX Atual** no topo: ele atualiza a cada segundo, com o mesmo instante em UTC logo abaixo."
  - "Para transformar um timestamp em data, cole-o em **Timestamp → Data** e clique em **Converter**. Valores de 10 dígitos são lidos como segundos, os de 13 como milissegundos."
  - "Leia o resultado: primeiro a data em UTC, depois o mesmo instante no fuso horário local do seu navegador."
  - "Para gerar um timestamp, escolha data e hora em **Data → Timestamp** (horário local, ao segundo) e clique em **Converter**."
  - "Use o botãozinho de copiar ao lado de cada resultado para mandá-lo para a área de transferência."
faq:
  - q: "O que é um timestamp Unix?"
    a: "O número de segundos passados desde 00:00:00 UTC de 1º de janeiro de 1970, o \"epoch\" do Unix, sem contar segundos bissextos. Num dado instante ele é igual no mundo todo, e por isso servidores, bancos de dados e logs o usam: 1700000000 é 14 de novembro de 2023 às 22:13:20 UTC, seja qual for o seu fuso."
  - q: "Segundos ou milissegundos?"
    a: "Ferramentas Unix, PHP, o `time.time()` do Python (como inteiro) e a maioria dos bancos de dados usam segundos, hoje com 10 dígitos. O `Date.now()` do JavaScript, o `System.currentTimeMillis()` do Java e muitas APIs usam milissegundos, 13 dígitos. O ChronoSync trata entradas com 13 dígitos ou mais como milissegundos e marca o resultado com (ms)."
  - q: "Por que a data convertida parece uma ou duas horas errada?"
    a: "Porque um timestamp não tem fuso horário; só a exibição dele tem. Compare a linha UTC, não a local, com o servidor ou os logs, que normalmente estão em UTC. O horário de verão explica diferenças que só aparecem em parte do ano."
  - q: "O que é o problema do ano 2038?"
    a: "Sistemas que guardam timestamps como inteiros com sinal de 32 bits estouram em 2147483647, ou seja, às 03:14:07 UTC de 19 de janeiro de 2038. Depois disso o valor vira negativo e as datas voltam para 1901. Sistemas modernos usam 64 bits, mas dispositivos embarcados e formatos de arquivo antigos ainda são afetados."
  - q: "Funciona com datas antes de 1970?"
    a: "Sim. Timestamps negativos contam os segundos antes do epoch: -86400 é 31 de dezembro de 1969 às 00:00 UTC. Digite o sinal de menos e converta normalmente."
  - q: "Como pegar o timestamp atual no código?"
    a: "Bash: `date +%s`. Python: `int(time.time())`. JavaScript: `Math.floor(Date.now() / 1000)`. PHP: `time()`. SQL (PostgreSQL): `extract(epoch from now())`. PowerShell: `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`."
---

## Como funciona

É tudo JavaScript com o objeto `Date` do navegador, que guarda o tempo internamente como milissegundos desde o epoch.

**Relógio ao vivo.** A cada segundo a página calcula `Math.floor(Date.now() / 1000)` e mostra ao lado do `toISOString()` do mesmo instante, no formato `AAAA-MM-DD HH:MM:SS UTC`.

**Timestamp → data.** A entrada precisa ser um inteiro, podendo ser negativo. Se tiver 13 dígitos ou mais, é tratada como milissegundos; senão, é multiplicada por 1000. A `Date` resultante aparece duas vezes:

1. em **UTC**, via `toISOString()`, a forma sem ambiguidade para comparar com logs e servidores;
2. no **horário local**, via `toLocaleString()`, com o fuso e o formato de data do seu navegador.

**Data → timestamp.** O seletor é um `<input type="datetime-local">`, que não tem fuso próprio; o navegador o interpreta no seu fuso local. `getTime() / 1000`, arredondado para baixo, dá os segundos epoch. O seletor já vem preenchido com o horário local atual.

| Timestamp | Data UTC | Observação |
|---|---|---|
| `0` | 1970-01-01 00:00:00 | O epoch |
| `1000000000` | 2001-09-09 01:46:40 | Primeiro timestamp de 10 dígitos |
| `1700000000` | 2023-11-14 22:13:20 | |
| `2000000000` | 2033-05-18 03:33:20 | |
| `2147483647` | 2038-01-19 03:14:07 | Maior valor com sinal de 32 bits |
| `-86400` | 1969-12-31 00:00:00 | Um dia antes do epoch |

Segundos bissextos não fazem parte do tempo Unix, então um timestamp corresponde a um único instante UTC (fora o raro segundo bissexto em si) e dois timestamps diferem exatamente pelo número de segundos entre eles.

## Casos de uso

- **Ler logs e JWTs.** Transforme `exp`, `iat` e campos de log como `1729771200` em uma data compreensível.
- **Depurar fusos horários.** Veja na hora se um valor salvo é meia-noite UTC ou meia-noite local.
- **Escrever consultas.** Pegue o timestamp de "1º de março de 2026 00:00" para colar num `WHERE` de SQL ou num filtro de API.
- **Converter entre linguagens.** Confira se um valor vindo do JavaScript (ms) e outro do Python (s) descrevem o mesmo momento.
- **Cron e agendamento.** Verifique quando uma tarefa agendada em tempo epoch vai rodar de verdade.
