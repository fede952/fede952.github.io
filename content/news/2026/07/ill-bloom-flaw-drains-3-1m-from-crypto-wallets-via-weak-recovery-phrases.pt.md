---
title: "Falha Ill Bloom Drena US$ 3,1 Milhões de Carteiras Cripto por Meio de Frases de Recuperação Fracas"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "pt"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes exploram uma vulnerabilidade na geração de frases de recuperação de carteiras de criptomoedas, apelidada de Ill Bloom, para roubar US$ 3,1 milhões em uma varredura coordenada."
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "carteiras de criptomoedas"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes exploram uma vulnerabilidade na geração de frases de recuperação de carteiras de criptomoedas, apelidada de Ill Bloom, para roubar US$ 3,1 milhões em uma varredura coordenada.

{{< cyber-report severity="High" source="The Hacker News" target="carteiras de criptomoedas" >}}

A empresa de segurança Coinspect divulgou uma vulnerabilidade em software de carteira de criptomoedas, chamada Ill Bloom, que permite que atacantes drenem fundos explorando aleatoriedade fraca na geração de frases de recuperação. A falha afeta como algumas carteiras criam a frase mnemônica que controla o acesso aos fundos da carteira. Quando a aleatoriedade é insuficiente, um atacante pode calcular a frase e obter controle total sobre a carteira.

{{< ad-banner >}}

A Coinspect confirmou que atacantes já exploraram essa vulnerabilidade em uma varredura coordenada em maio, roubando aproximadamente US$ 3,1 milhões de várias carteiras. A data exata e o escopo completo do ataque não foram divulgados, mas o incidente destaca a importância crítica da geração segura de números aleatórios em aplicações criptográficas.

Usuários de carteiras são aconselhados a verificar se seu software usa geradores de números aleatórios criptograficamente seguros e a considerar migrar fundos para carteiras com implementações de aleatoriedade auditadas. Desenvolvedores devem revisar suas fontes de entropia e garantir conformidade com padrões da indústria como BIP39.

{{< netrunner-insight >}}

Este incidente ressalta o perigo de confiar em entropia fraca na geração de chaves criptográficas. Analistas de SOC devem monitorar transações incomuns de carteiras ou movimentações em massa de fundos, enquanto engenheiros DevSecOps devem auditar toda geração de números aleatórios em aplicações críticas de segurança. Sempre presuma que aleatoriedade previsível será explorada.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
