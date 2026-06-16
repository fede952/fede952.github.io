---
title: "Le ransomware DragonForce utilise les relais Microsoft Teams pour masquer le trafic C2"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "fr"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Le ransomware DragonForce déploie le malware personnalisé 'Backdoor.Turn' pour dissimuler le trafic de commande et contrôle dans l'infrastructure de relais Microsoft Teams."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "infrastructure de relais Microsoft Teams"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le ransomware DragonForce déploie le malware personnalisé 'Backdoor.Turn' pour dissimuler le trafic de commande et contrôle dans l'infrastructure de relais Microsoft Teams.

{{< cyber-report severity="High" source="BleepingComputer" target="infrastructure de relais Microsoft Teams" >}}

Le groupe de ransomware DragonForce a été observé utilisant un malware personnalisé nommé 'Backdoor.Turn' pour cacher son trafic de commande et contrôle (C2) dans l'infrastructure de relais Microsoft Teams. Cette technique permet aux attaquants de mélanger les communications malveillantes avec le trafic légitime de Teams, rendant la détection plus difficile pour les défenseurs réseau.

{{< ad-banner >}}

En abusant des relais Microsoft Teams, le gang de ransomware peut contourner les contrôles de sécurité réseau traditionnels qui peuvent ne pas scruter le trafic vers des services de confiance. Le malware exploite probablement les API ou protocoles de Teams pour tunneliser les données C2, échappant à la détection basée sur les signatures et permettant un accès persistant aux réseaux compromis.

Les organisations utilisant Microsoft Teams doivent surveiller les schémas de trafic sortant inhabituels vers les points de terminaison Teams et envisager de mettre en place une inspection supplémentaire pour les tunnels chiffrés. Cet incident souligne la tendance croissante des groupes de ransomware à adopter des techniques de living-off-the-land et d'abus de services de confiance pour échapper à la détection.

{{< netrunner-insight >}}

Pour les analystes SOC, cela souligne la nécessité de définir une base de référence du trafic Teams normal et d'alerter sur les anomalies telles que des volumes de données inattendus ou des connexions à des points de terminaison Teams non standard. Les équipes DevSecOps doivent examiner les permissions d'intégration Teams et restreindre l'accès API inutile pour réduire la surface d'attaque pour l'abus de relais.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
