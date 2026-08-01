---
title: "Atualização Falsa de Navegador em Wi-Fi de Hotel Entrega RAT CornFlake"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "pt"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "A Microsoft alerta sobre a operação CaptiveCrunch que usa Wi-Fi de hotéis sequestrado para empurrar atualizações falsas e entregar o malware de vigilância CornFlake."
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "Usuários de Wi-Fi de hotel"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A Microsoft alerta sobre a operação CaptiveCrunch que usa Wi-Fi de hotéis sequestrado para empurrar atualizações falsas e entregar o malware de vigilância CornFlake.

{{< cyber-report severity="High" source="The Hacker News" target="Usuários de Wi-Fi de hotel" >}}

A Microsoft divulgou uma nova campanha rastreada como CaptiveCrunch, que aproveita redes Wi-Fi de hotéis sequestradas para servir atualizações falsas de navegador. Essas atualizações são, na verdade, um trojan de acesso remoto (RAT) chamado CornFlake, capaz de capturar imagens de webcam, áudio de microfone e teclas digitadas, efetivamente transformando dispositivos infectados em ferramentas de vigilância.

{{< ad-banner >}}

A operação é atribuída ao Storm-2945, que a Microsoft avalia como um subcluster operacional do conhecido grupo de ameaças Midnight Blizzard. Isso sugere um alto nível de sofisticação e recursos, pois a cadeia de ataque envolve comprometer a infraestrutura de rede dos hotéis para interceptar e redirecionar o tráfego dos usuários para páginas de atualização maliciosas.

Embora o relatório não especifique um CVE ou pontuação CVSS em particular, o vetor de ataque é notável por usar um ambiente confiável (Wi-Fi de hotel) para entregar malware. Viajantes e profissionais de negócios estão particularmente em risco, pois muitas vezes dependem de Wi-Fi público e podem ser mais propensos a aceitar prompts de atualização do navegador sem escrutínio.

{{< netrunner-insight >}}

Esta campanha ressalta a importância de tratar qualquer prompt de atualização de navegador em redes não confiáveis com suspeita. Analistas de SOC devem monitorar conexões de saída incomuns de endpoints que se conectaram recentemente a Wi-Fi de hotel ou público, e considerar bloquear ou sinalizar domínios relacionados a atualizações que não estejam na lista de permissões da organização. Para DevSecOps, impor políticas de atualização rigorosas e usar VPNs de nível empresarial para trabalhadores remotos pode mitigar o risco de ataques desse tipo watering-hole.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
