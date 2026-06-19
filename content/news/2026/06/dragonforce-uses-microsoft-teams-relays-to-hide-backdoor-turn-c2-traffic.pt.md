---
title: "DragonForce usa relays do Microsoft Teams para ocultar tráfego C2 do Backdoor.Turn"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "pt"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "O grupo de ransomware DragonForce implanta o RAT personalizado em Go Backdoor.Turn, ocultando o tráfego C2 em relays do Microsoft Teams, visando uma grande empresa de serviços dos EUA."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "Grande empresa de serviços dos EUA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O grupo de ransomware DragonForce implanta o RAT personalizado em Go Backdoor.Turn, ocultando o tráfego C2 em relays do Microsoft Teams, visando uma grande empresa de serviços dos EUA.

{{< cyber-report severity="High" source="The Hacker News" target="Grande empresa de serviços dos EUA" >}}

Atores de ameaças associados ao grupo de ransomware DragonForce foram observados usando um trojan de acesso remoto (RAT) personalizado em Go chamado Backdoor.Turn para ocultar o tráfego de comando e controle (C2) dentro da infraestrutura de relay do Microsoft Teams. O backdoor foi implantado contra uma grande empresa de serviços dos EUA, de acordo com descobertas da Symantec e Carbon Black, de propriedade da Broadcom.

{{< ad-banner >}}

Ao aproveitar relays legítimos do Microsoft Teams, os atacantes podem misturar tráfego malicioso com comunicações comerciais normais, dificultando a detecção pelos defensores de rede. O RAT em Go fornece aos atacantes acesso persistente e a capacidade de executar comandos, exfiltrar dados e implantar payloads adicionais.

Essa técnica destaca a evolução das táticas dos grupos de ransomware para evadir ferramentas tradicionais de monitoramento de rede. Organizações que usam o Microsoft Teams devem revisar suas configurações de segurança e monitorar padrões anômalos de tráfego de relay.

{{< netrunner-insight >}}

Analistas de SOC devem monitorar tráfego incomum de relay do Microsoft Teams, especialmente de endpoints não padrão ou fora do horário comercial. Equipes de DevSecOps devem impor listas de permissões estritas de aplicativos e inspecionar o tráfego do Teams em busca de túneis criptografados que possam indicar comunicação C2. Este ataque ressalta a necessidade de princípios de confiança zero mesmo para plataformas de colaboração confiáveis.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
