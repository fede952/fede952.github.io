---
title: "Calculadora CVSS 4.0 (e CVSS 3.1)"
description: "Calcule a pontuação CVSS 4.0 com o método MacroVector oficial do FIRST, ou as pontuações CVSS 3.1 base, temporal e de ambiente. Cole um vetor ou clique."
intro: "Escolha as métricas ou cole uma string de vetor para obter a pontuação **CVSS 4.0**, a gravidade, a nomenclatura (CVSS-B, BT, BE ou BTE) e o MacroVector, calculados com **a lógica de pontuação e a tabela oficiais do FIRST**. Uma segunda aba pontua vetores **CVSS 3.1**, incluindo as pontuações temporal e de ambiente. Compartilhe um resultado com um link `?vector=`. Tudo roda no seu navegador."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["calculadora cvss 4.0", "calculadora cvss", "calcular pontuação cvss", "calculadora cvss 3.1", "pontuação cvss vulnerabilidade", "vetor cvss", "cvss 4 macrovector", "gravidade vulnerabilidade cvss"]
tags: ["security", "vulnerability", "cvss", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/cvss-calculator/"
tool_title: "Calculadora CVSS 4.0 e 3.1"
tool_height: 1400
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Escolha **CVSS 4.0** ou **CVSS 3.1** nas abas."
  - "Cole uma **string de vetor** (por exemplo, de um boletim de segurança) ou clique no valor de cada métrica base."
  - "Se quiser, abra as métricas **de ameaça**, **de ambiente** ou, na 4.0, **suplementares** para ajustar a pontuação ao seu ambiente."
  - "Leia a **pontuação**, a **gravidade** e, na 4.0, a **nomenclatura** que diz quais grupos de métricas foram usados."
  - "Clique em **Copiar vetor** para relatórios, ou **Copiar link** para compartilhar uma página que abre com o mesmo vetor."
faq:
  - q: "A pontuação é a mesma da calculadora oficial do FIRST?"
    a: "É calculada com o mesmo método: o código CVSS 4.0 desta ferramenta é uma adaptação da função de pontuação da calculadora oficial do FIRST e usa a tabela de MacroVectors dela sem alterações. Os testes verificam todos os vetores de exemplo publicados na página de exemplos do CVSS 4.0 do FIRST e comparam 20.000 vetores aleatórios com o código oficial; o CVSS 3.1 é comparado da mesma forma com a calculadora 3.1 do FIRST. Este site não é afiliado ao FIRST."
  - q: "Por que o CVSS 4.0 não usa uma fórmula como o 3.1?"
    a: "O CVSS 4.0 agrupa as métricas em seis conjuntos de equivalência e associa cada combinação, um MacroVector, a uma pontuação definida por especialistas. A pontuação final parte da do MacroVector e é ajustada conforme a distância entre o vetor e o vetor mais grave do mesmo MacroVector. Por isso a ferramenta mostra o MacroVector ao lado da pontuação."
  - q: "O que significam CVSS-B, CVSS-BT, CVSS-BE e CVSS-BTE?"
    a: "Indicam quais grupos de métricas uma pontuação CVSS 4.0 inclui: B só a base, T acrescenta as métricas de ameaça (maturidade do exploit), E acrescenta as de ambiente. A pontuação base de um boletim é CVSS-B; com informações de exploit e o seu próprio ambiente, ela vira CVSS-BTE."
  - q: "Quais são as faixas de gravidade?"
    a: "A escala qualitativa é a mesma no CVSS 3.1 e no 4.0: Nenhuma 0.0, Baixa 0.1–3.9, Média 4.0–6.9, Alta 7.0–8.9, Crítica 9.0–10.0."
  - q: "As métricas suplementares mudam a pontuação?"
    a: "Não. Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort e Provider Urgency acrescentam contexto para decisões, mas não afetam a pontuação CVSS 4.0. Elas continuam aparecendo no vetor."
  - q: "Algo é enviado para um servidor?"
    a: "Não. O cálculo acontece no seu navegador e a ferramenta não faz requisições de rede. Um link compartilhado contém só a string do vetor."
---

## Como funciona

### CVSS 4.0: MacroVectors e a tabela oficial

As 11 métricas base, mais a maturidade do exploit e os requisitos de ambiente, são divididas em seis grupos de equivalência (EQ1–EQ6), como "quão alcançável é o sistema" (vetor de ataque, privilégios necessários, interação do usuário) ou "quão grave é o impacto no sistema vulnerável". O nível de cada grupo forma um **MacroVector** de seis dígitos, e a tabela do FIRST dá uma pontuação a cada um dos 270 valores possíveis. A pontuação do vetor é esse valor menos um ajuste baseado na distância até o vetor mais grave do mesmo MacroVector, arredondada para uma casa decimal. A implementação segue passo a passo a calculadora oficial do FIRST e usa a tabela como foi publicada (licença BSD-2-Clause, creditada no código-fonte).

### Métricas de ambiente e de ameaça

Sem valor definido, a **maturidade do exploit** assume o pior caso (Attacked) e os requisitos de segurança valem High, como determina a especificação. As métricas **modificadas** substituem a métrica base correspondente no seu ambiente: por exemplo, um sistema acessível só pela rede interna pode usar Modified Attack Vector: Adjacent.

### CVSS 3.1

A segunda aba aplica as equações da especificação CVSS 3.1: a pontuação base a partir do impacto e da explorabilidade (com o ajuste de escopo), a temporal a partir da maturidade do código de exploit, do nível de correção e da confiança do relato, e a de ambiente com as métricas modificadas e a função de arredondamento da 3.1.

## Casos de uso

- **Triar boletins** — cole o vetor de um registro CVE ou de um boletim do fabricante e veja o que define a pontuação.
- **Pontuar suas descobertas** — para um relatório de teste de invasão ou um envio de bug bounty, com um vetor que outros podem conferir.
- **Adaptar ao seu ambiente** — use as métricas de ambiente para classificar a mesma vulnerabilidade de forma diferente em sistemas expostos à internet e internos.
- **Comparar 3.1 e 4.0** — muitos bancos de dados ainda publicam os dois; pontue o mesmo problema em cada aba.
- **Aprender as métricas** — cada valor tem um rótulo e a pontuação muda a cada clique.
