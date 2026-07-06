---
title: "GhostPrint: Teste de Impressão Digital do Navegador — Você é Rastreável?"
description: "Veja a impressão digital invisível que seu navegador entrega a cada site — GPU, canvas, fontes, áudio e mais — com uma pontuação de unicidade. 100% no navegador: nada é enviado."
date: 2026-07-06
tags: ["privacy", "security", "developer-tools", "fingerprinting"]
keywords: ["teste impressão digital navegador", "sou único", "impressão digital do dispositivo", "canvas fingerprint", "quão rastreável eu sou", "fingerprinting do navegador", "impressão webgl", "impressão de áudio", "teste de privacidade online", "teste anti-rastreamento"]
layout: "tool"
draft: false
tool_file: "/tools/ghostprint/"
tool_height: "2200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "GhostPrint — Teste de Impressão Digital do Navegador", "description": "Teste gratuito no lado do cliente que pontua quão único e rastreável seu navegador é a partir de GPU, canvas, áudio, fontes e mais.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Por que uma impressão digital vence um cookie

Cookies são fáceis de bloquear. Sua **impressão digital do navegador** não é. A forma exata como seu dispositivo, GPU, fontes, tela e configurações se combinam cria um identificador que te segue entre sites — e ele **sobrevive ao modo anônimo, a cookies apagados e à maioria da navegação "privada".** O GhostPrint mostra a sua em segundos, com uma pontuação de unicidade e o detalhamento de cada sinal que vaza.

O detalhe que prova o ponto: cada sinal abaixo é lido **dentro do seu navegador** e enviado para **lugar nenhum** — sem upload, sem logs, sem servidor. Mas qualquer site que você visita pode ler esses mesmos valores silenciosamente, sem pedir permissão, e as redes de publicidade e antifraude fazem exatamente isso. Recarregue a página e seus dados somem; os rastreadores não oferecem esse botão.

## O que o GhostPrint lê

- **Hardware e GPU** — sua placa gráfica (via WebGL), núcleos da CPU, memória e métricas de tela
- **Impressões de renderização** — hashes de canvas e áudio: peculiaridades em nível de pixel e amostra únicas do seu sistema
- **Ambiente** — fontes instaladas, fuso horário, idiomas, plataforma e preferências de exibição
- **Sinais de privacidade** — estado de cookies, Do-Not-Track e Global Privacy Control

## Como apagar o fantasma

- **Tor Browser** é o padrão-ouro — todo usuário é deliberadamente feito idêntico aos demais.
- **Firefox** oferece `privacy.resistFingerprinting`; **Brave** randomiza canvas e áudio por padrão.
- Extensões anti-fingerprint e desativar o WebGL ajudam — e, paradoxalmente, hardware exótico e fontes raras te tornam *mais* identificável, não menos.

Execute a varredura acima para obter sua pontuação de unicidade, depois baixe um cartão compartilhável e compare seus outros navegadores.
