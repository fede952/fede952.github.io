---
title: "Ransomware DragonForce usa relays do Microsoft Teams para ocultar tráfego C2"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "pt"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "O ransomware DragonForce implanta o malware personalizado 'Backdoor.Turn' para ocultar o tráfego de comando e controle dentro da infraestrutura de relay do Microsoft Teams."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "infraestrutura de relay do Microsoft Teams"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O ransomware DragonForce implanta o malware personalizado 'Backdoor.Turn' para ocultar o tráfego de comando e controle dentro da infraestrutura de relay do Microsoft Teams.

{{< cyber-report severity="High" source="BleepingComputer" target="infraestrutura de relay do Microsoft Teams" >}}

O grupo de ransomware DragonForce foi observado usando um malware personalizado chamado 'Backdoor.Turn' para ocultar seu tráfego de comando e controle (C2) dentro da infraestrutura de relay do Microsoft Teams. Essa técnica permite que os atacantes misturem comunicações maliciosas com o tráfego legítimo do Teams, dificultando a detecção pelos defensores de rede.

{{< ad-banner >}}

Ao abusar dos relays do Microsoft Teams, o grupo de ransomware pode contornar controles de segurança de rede tradicionais que podem não examinar o tráfego para serviços confiáveis. O malware provavelmente utiliza APIs ou protocolos do Teams para tunelar dados C2, evadindo a detecção baseada em assinaturas e permitindo acesso persistente a redes comprometidas.

Organizações que usam Microsoft Teams devem monitorar padrões incomuns de tráfego de saída para endpoints do Teams e considerar a implementação de inspeção adicional para túneis criptografados. Este incidente destaca a tendência crescente de grupos de ransomware adotarem técnicas de living-off-the-land e abuso de serviços confiáveis para evadir a detecção.

{{< netrunner-insight >}}

Para analistas de SOC, isso ressalta a necessidade de basear o tráfego normal do Teams e alertar sobre anomalias, como volumes inesperados de dados ou conexões a endpoints não padrão do Teams. As equipes de DevSecOps devem revisar as permissões de integração do Teams e restringir o acesso desnecessário à API para reduzir a superfície de ataque para abuso de relay.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
