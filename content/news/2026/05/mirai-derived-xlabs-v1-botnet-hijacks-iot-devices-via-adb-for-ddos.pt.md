---
title: "Botnet xlabs_v1 Derivado do Mirai Sequestra Dispositivos IoT via ADB para DDoS"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "pt"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Pesquisadores descobrem xlabs_v1, um novo botnet baseado no Mirai que explora portas Android Debug Bridge expostas para recrutar dispositivos IoT em uma rede DDoS."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "Dispositivos IoT com ADB exposto"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pesquisadores descobrem xlabs_v1, um novo botnet baseado no Mirai que explora portas Android Debug Bridge expostas para recrutar dispositivos IoT em uma rede DDoS.

{{< cyber-report severity="High" source="The Hacker News" target="Dispositivos IoT com ADB exposto" >}}

Pesquisadores de cibersegurança identificaram um novo botnet derivado do Mirai, autoidentificado como xlabs_v1, que tem como alvo dispositivos expostos à internet que executam o Android Debug Bridge (ADB). O botnet visa alistar dispositivos comprometidos em uma rede capaz de lançar ataques de negação de serviço distribuída (DDoS).

{{< ad-banner >}}

A descoberta foi feita pela Hunt.io após identificarem um diretório exposto em um servidor hospedado na Holanda. O malware explora o ADB, uma ferramenta de linha de comando usada para depuração de dispositivos Android, que muitas vezes fica exposta em dispositivos IoT, permitindo que atacantes remotos obtenham acesso não autorizado.

Esta campanha destaca a ameaça contínua de variantes do Mirai visando dispositivos IoT mal protegidos. As organizações são aconselhadas a desabilitar o ADB em dispositivos de produção e restringir o acesso à rede para evitar tal sequestro.

{{< netrunner-insight >}}

Para analistas de SOC, monitore conexões ADB inesperadas de IPs externos. Equipes de DevSecOps devem garantir que o ADB esteja desabilitado em builds de produção e que os dispositivos IoT sejam segmentados das redes críticas para mitigar o alcance deste botnet.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
