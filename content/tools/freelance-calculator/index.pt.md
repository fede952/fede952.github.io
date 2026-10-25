---
title: "Calculadora de Valor Hora Freelancer"
description: "Calcule o valor hora e a diária de que você precisa como freelancer a partir do líquido desejado, dias e horas faturáveis, impostos e despesas. Grátis."
intro: "O **RateMate** transforma a renda que você quer levar para casa no valor que precisa cobrar. Informe o salário líquido anual desejado, os dias e horas faturáveis, a alíquota de impostos e as despesas mensais, e veja na hora seu valor hora, sua diária e quanto precisa faturar por mês."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["calculadora valor hora freelancer", "quanto cobrar como freelancer", "calcular valor da hora", "calculadora de diária", "valor hora autônomo", "preço freelancer", "valor hora consultor", "como precificar serviços"]
tags: ["freelance", "finanças", "negócios", "ferramenta"]
app_category: "FinanceApplication"
tool_file: "/tools/freelance-calculator/"
tool_title: "RateMate, calculadora de valor hora freelancer"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Escolha a moeda ($, € ou £) e informe o **Desired Annual Net Salary**: o que você quer guardar depois de impostos e custos do negócio."
  - "Ajuste **Billable Days per Year**. O padrão é 220; desconte com sinceridade férias, licenças, administração e tempo de prospecção."
  - "Ajuste **Daily Billable Hours**: as horas que você realmente consegue faturar, normalmente 5–7, não 8."
  - "Mova o controle **Tax Rate** para a sua alíquota efetiva de impostos e contribuições e informe as **Monthly Expenses** (software, equipamento, seguros, coworking, contador)."
  - "Leia **Your Hourly Rate**, o **Daily Rate** e o **Monthly Gross** que você precisa faturar. O gráfico de rosca mostra como cada real faturado se divide entre renda, impostos e despesas."
faq:
  - q: "Como calcular meu valor hora como freelancer?"
    a: "Comece pela renda de que você precisa, não pelo que os outros cobram. Some as despesas anuais do negócio, converta o total para bruto considerando os impostos e divida pelas horas que você consegue faturar de forma realista. Com os valores padrão (60.000 líquidos, 500 de despesas por mês, 25% de impostos, 220 dias de 6 horas faturáveis) fica (60.000 + 6.000) ÷ 0,75 = 88.000 por ano, 400 por dia, cerca de 67 por hora."
  - q: "Quantos dias faturáveis por ano devo considerar?"
    a: "Um ano tem uns 260 dias úteis. Tire os feriados (8–14, conforme o país), 20–30 dias de férias, alguns dias de doença e o tempo de vendas, administração e estudo. A maioria dos freelancers fica entre 180 e 220 dias faturáveis; quem está começando e ainda não tem clientes fixos costuma faturar menos."
  - q: "Por que as horas faturáveis são menos que as horas trabalhadas?"
    a: "E-mails, notas fiscais, propostas, reuniões que não dá para cobrar e trocas de contexto consomem tempo. Seis horas faturáveis em um dia de oito é um número comum e sustentável. Se você fatura oito horas todo dia, provavelmente trabalha dez."
  - q: "Que alíquota de impostos devo informar?"
    a: "A sua alíquota *efetiva*: impostos mais contribuições divididos pelo faturamento bruto, não a faixa marginal mais alta. Ela muda muito conforme o país e o regime (no Brasil, por exemplo, entre MEI, Simples Nacional e lucro presumido); para uma primeira estimativa use os números do ano passado ou pergunte ao contador, e teste alguns valores."
  - q: "A calculadora considera as despesas dedutíveis?"
    a: "Não. Ela aplica a alíquota sobre todo o bruto, despesas incluídas, o que dá um valor um pouco mais alto e prudente. Onde as despesas são totalmente dedutíveis, o bruto necessário é líquido ÷ (1 − alíquota) + despesas: com os valores padrão, 86.000 em vez de 88.000, cerca de 65 por hora em vez de 67."
  - q: "Cobrar por hora, por diária ou por projeto?"
    a: "Use o valor hora como piso. Muitos freelancers orçam por diária (mostrada aqui) ou com um preço fechado por projeto calculado a partir dela, que premia a eficiência em vez das horas. Seja qual for o orçamento, confira que ele nunca fique abaixo do valor hora desta calculadora."
  - q: "Meus dados financeiros ficam salvos?"
    a: "Não. O cálculo acontece no seu navegador e nada é salvo ou enviado. Fechou a página, os números somem."
---

## Como funciona

O RateMate faz a conta de trás para a frente, a partir do dinheiro que você quer guardar.

1. **Despesas anuais** = despesas mensais × 12.
2. **Faturamento bruto anual necessário** = (líquido desejado + despesas anuais) ÷ (1 − alíquota).
   A alíquota é tratada como uma fatia fixa de tudo o que você fatura, então a fórmula converte para bruto tanto o seu salário quanto os custos.
3. **Impostos anuais** = bruto − líquido − despesas.
4. **Diária** = bruto ÷ dias faturáveis.
5. **Valor hora** = diária ÷ horas faturáveis por dia.
6. **Bruto mensal** = bruto ÷ 12, o que você precisa faturar em média por mês.

O gráfico de rosca, desenhado com Chart.js, mostra as três fatias do bruto: renda líquida, impostos e despesas. Cada campo recalcula enquanto você digita, então dá para arrastar o controle de impostos (0–60%) e ver o valor mudar.

### Exemplo prático

| Dado | Valor |
|---|---|
| Líquido desejado | 60.000 |
| Despesas mensais | 500 (6.000 por ano) |
| Alíquota | 25% |
| Dias faturáveis | 220 |
| Horas faturáveis por dia | 6 |

Bruto = 66.000 ÷ 0,75 = **88.000** por ano → **400** por dia → **≈ 67** por hora → **≈ 7.333** a faturar por mês. De cada 100 faturados, cerca de 68 são renda, 25 impostos e 7 cobrem despesas.

Mude uma única premissa e você entende por que os valores variam tanto. Com 180 dias faturáveis o valor hora sobe para uns 81; com 5 horas faturáveis por dia em vez de 6, para 80. A alavanca mais forte geralmente não é a alíquota, e sim quanto do seu tempo você consegue faturar de verdade.

### O que o modelo deixa de fora

A calculadora fica de propósito em uma única alíquota efetiva. Ela não modela faixas progressivas, impostos sobre o serviço que você repassa ao cliente, previdência além do que você incluir no "líquido" nem os períodos sem trabalho entre contratos. Se isso se aplica a você, acrescente uma margem ou aumente o líquido.

## Casos de uso

- **Virar freelancer.** Transforme seu salário de CLT no valor que você precisa cobrar, e entenda logo por que um freelancer precisa cobrar bem mais que salário ÷ 2.080 horas.
- **Montar um orçamento.** Confira se o preço de um projeto, dividido pelos dias que ele vai levar, continua acima da sua diária.
- **Reajustar seus preços.** Coloque as despesas e a alíquota reais deste ano e veja se o valor atual ainda cobre tudo.
- **Comparar propostas.** Compare a diária de um contrato com um salário fixo em condições iguais.
- **Planejar um período sabático ou um curso.** Reduza os dias faturáveis e veja quanto o valor precisa subir para manter a mesma renda.
