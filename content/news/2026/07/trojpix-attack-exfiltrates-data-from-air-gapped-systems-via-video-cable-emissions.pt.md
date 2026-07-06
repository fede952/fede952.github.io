---
title: "Ataque TrojPix Exfiltra Dados de Sistemas Isolados via Emissões de Cabo de Vídeo"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "pt"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "Pesquisadores demonstram TrojPix, uma técnica que vaza dados de computadores isolados modulando pixels na tela para emitir sinais de rádio fracos a partir de cabos de vídeo, exigindo acesso prévio de malware."
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "Sistemas isolados"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pesquisadores demonstram TrojPix, uma técnica que vaza dados de computadores isolados modulando pixels na tela para emitir sinais de rádio fracos a partir de cabos de vídeo, exigindo acesso prévio de malware.

{{< cyber-report severity="Medium" source="The Hacker News" target="Sistemas isolados" >}}

Pesquisadores da Universidade de Shandong revelaram o TrojPix, um ataque inovador que exfiltra dados de computadores isolados explorando emissões eletromagnéticas de cabos de vídeo. A técnica altera sutilmente os pixels na tela de forma imperceptível ao olho humano, fazendo com que o cabo de vídeo irradie um sinal de rádio fraco que pode ser capturado e decodificado por um receptor próximo.

{{< ad-banner >}}

O TrojPix requer instalação prévia de malware no sistema alvo para manipular os valores dos pixels. Essa abordagem alcança taxas de transferência de dados significativamente maiores em comparação com canais ocultos anteriores para sistemas isolados, tornando-se uma ameaça prática para ambientes altamente seguros. O ataque destaca o desafio contínuo de proteger dados mesmo em redes fisicamente isoladas.

Embora a técnica seja sofisticada, sua dependência de malware pré-existente limita sua aplicabilidade. As organizações devem focar em prevenir a infecção inicial por meio de segurança robusta de endpoints e monitorar emissões eletromagnéticas incomuns em áreas sensíveis.

{{< netrunner-insight >}}

Para analistas de SOC, o TrojPix ressalta que sistemas isolados não estão imunes à exfiltração de dados. Monitore sinais eletromagnéticos anômalos perto de estações de trabalho sensíveis e aplique segurança física rigorosa. Equipes de DevSecOps devem considerar blindar cabos de vídeo e implementar detecção de anomalias em nível de pixel quando viável.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
