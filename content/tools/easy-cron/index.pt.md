---
title: "Gerador de Expressões Cron Explicadas"
description: "Monte expressões cron de forma visual, traduza-as para linguagem simples e veja as próximas 5 execuções. Gerador de crontab grátis para Linux e CI."
intro: "O **EasyCron** monta uma expressão cron com cliques, traduz para linguagem simples uma que você já tem e lista as próximas cinco execuções. Ele cobre a sintaxe padrão de crontab com cinco campos usada pelo cron no Linux, pelos CronJobs do Kubernetes e pela maioria dos agendadores de CI."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["gerador cron", "expressão cron", "crontab generator", "cron a cada 5 minutos", "exemplos de crontab", "explicar expressão cron", "agendar tarefa cron", "próxima execução cron"]
tags: ["linux", "devops", "cron", "ferramenta"]
app_category: "DeveloperApplication"
tool_file: "/tools/easy-cron/"
tool_title: "EasyCron, gerador de expressões cron"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Comece por um **preset** (a cada 5 minutos, dias úteis às 9h, mensal no dia 1…) ou pelo padrão `* * * * *`."
  - "Use as abas **Minute, Hour, Day, Month, Weekday** para definir cada campo: todos os valores, um intervalo como a cada 15 minutos ou valores específicos escolhidos em uma grade. Botões rápidos cobrem escolhas comuns, como horário comercial ou dias úteis."
  - "Veja a expressão, a descrição e as **Next 5 runs** se atualizarem a cada clique."
  - "Clique em **Copy** e cole a expressão no seu crontab, no manifesto do CronJob ou no arquivo de CI."
  - "Para entender um agendamento existente, cole-o no **Reverse Translator** e clique em **Parse**: você recebe a descrição e as próximas execuções, e o construtor o carrega para edição."
faq:
  - q: "O que significam os cinco campos de uma expressão cron?"
    a: "Na ordem: minuto (0–59), hora (0–23), dia do mês (1–31), mês (1–12) e dia da semana (0–6, domingo = 0). `30 2 * * 1` significa, então, às 02:30 de toda segunda-feira. Um asterisco quer dizer \"qualquer valor\" naquele campo."
  - q: "Como rodar uma tarefa cron a cada 5 minutos?"
    a: "`*/5 * * * *`. O `*/5` no campo de minutos significa a cada quinto minuto a partir de 0: 00, 05, 10 … 55. Da mesma forma, `0 */2 * * *` roda na hora cheia a cada duas horas e `*/15 9-17 * * 1-5` a cada 15 minutos no horário comercial em dias úteis."
  - q: "O que acontece se eu definir o dia do mês e o dia da semana ao mesmo tempo?"
    a: "O cron padrão (Vixie) executa a tarefa quando *qualquer um dos dois* bate, e não quando os dois batem. `0 9 1 * 1` roda às 09:00 no dia 1 de todo mês *e* em toda segunda-feira. O cálculo das próximas execuções do EasyCron segue a mesma regra, que surpreende muita gente."
  - q: "Em qual fuso horário aparecem as próximas execuções?"
    a: "No fuso horário do seu navegador. Um daemon cron usa o fuso da máquina onde roda, muitas vezes UTC em servidores e contêineres. Os CronJobs do Kubernetes usam o fuso do controller, a menos que você defina `spec.timeZone`. Se o seu servidor está em UTC, converta antes de confiar na lista."
  - q: "O EasyCron aceita segundos, nomes como MON ou JAN, ou @daily?"
    a: "Não. Ele foca na sintaxe portátil de cinco campos: números, `*`, intervalos como `1-5`, listas como `1,15`, passos como `*/10` e intervalos com passo como `0-30/10`. Segundos no estilo Quartz e `L`, `W`, `#`, `?` não são suportados. Escreva `0 0 * * *` no lugar de `@daily` e use `0` (não `7`) para domingo."
  - q: "Alguma coisa é enviada para um servidor?"
    a: "Não. O construtor, a descrição e o cálculo das execuções são JavaScript dentro desta página. A única coisa salva é a sua preferência de tema claro ou escuro, no localStorage do navegador."
---

## Como funciona

### Montando a expressão

Cada um dos cinco campos tem seu próprio estado: **every** (`*`), **interval** (`*/n`, com opções coerentes para cada campo, como 5, 10, 15 ou 30 minutos e 2, 3, 4, 6, 8 ou 12 horas) ou valores **específicos** escolhidos em uma grade. No modo específico, os números selecionados são ordenados e unidos por vírgulas (`0,15,30,45`). Se todos os valores possíveis forem selecionados, o campo volta a ser `*`. As cinco partes são unidas por espaços na expressão final.

### Interpretando e explicando

O tradutor reverso divide a expressão pelos espaços e exige exatamente cinco campos. Cada campo é expandido no conjunto de valores que ele cobre:

| Sintaxe | Exemplo | Vira |
|---|---|---|
| `*` | `*` nas horas | 0, 1, 2 … 23 |
| `*/n` | `*/15` nos minutos | 0, 15, 30, 45 |
| `a-b` | `1-5` nos dias da semana | seg … sex |
| `a-b/n` | `0-30/10` nos minutos | 0, 10, 20, 30 |
| lista | `1,15` nos dias | dia 1 e dia 15 |

A descrição (em inglês) é montada com regras que soam como uma pessoa falaria: `*/5 * * * *` vira "Every 5 minutes", `0 9 * * 1-5` vira "At 09:00, Monday through Friday" e `0 0 1 1 *` vira "At 00:00, on day 1 of the month, in January".

### Calculando as próximas execuções

A partir de um minuto à frente, o calculador avança no tempo pulando unidades inteiras que não podem bater: um mês fora do conjunto pula para o dia 1 do mês seguinte, um dia que não bate pula para a meia-noite do dia seguinte, uma hora que não bate pula para a próxima hora. Quando mês, dia, hora e minuto batem, o horário é registrado, até encontrar cinco execuções ou percorrer quatro anos. Por isso agendamentos impossíveis como `0 0 31 2 *` (31 de fevereiro) avisam que não há próximas execuções.

O teste do dia segue a semântica real do cron: se só um dos dois campos de dia estiver restrito, ele decide; se os dois estiverem, basta um deles bater.

## Casos de uso

- **Escrever uma linha de crontab** para backups, rotação de logs, renovação de certificados ou um script de limpeza sem precisar procurar de novo a ordem dos campos.
- **CronJobs do Kubernetes e pipelines de CI.** O `schedule:` do GitHub Actions, os agendamentos de pipelines do GitLab e o `spec.schedule` do Kubernetes usam os mesmos cinco campos.
- **Revisar o agendamento de outra pessoa.** Cole o enigmático `15 3 */2 * *` de uma configuração e leia "At 03:15, every 2nd day of the month".
- **Pegar erros antes da produção**, como uma tarefa pensada para "dias úteis às 9" que também roda no dia 1 do mês porque os dois campos de dia foram definidos.
- **Planejar janelas de manutenção.** Confira exatamente quando caem as próximas cinco execuções e ajuste para o fuso horário do servidor.
