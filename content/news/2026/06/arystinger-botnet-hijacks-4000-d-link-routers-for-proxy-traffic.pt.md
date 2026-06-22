---
title: "Botnet AryStinger sequestra mais de 4.000 roteadores D-Link para tráfego de proxy"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "pt"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma nova botnet chamada AryStinger comprometeu mais de 4.000 roteadores D-Link desatualizados, transformando-os em proxies para tráfego malicioso. Não há dados de CVE ou CVSS disponíveis."
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "Roteadores D-Link desatualizados"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma nova botnet chamada AryStinger comprometeu mais de 4.000 roteadores D-Link desatualizados, transformando-os em proxies para tráfego malicioso. Não há dados de CVE ou CVSS disponíveis.

{{< cyber-report severity="Medium" source="BleepingComputer" target="Roteadores D-Link desatualizados" >}}

Uma botnet de malware anteriormente não documentada chamada AryStinger comprometeu mais de 4.000 roteadores D-Link desatualizados em todo o mundo, de acordo com um relatório do BleepingComputer. A botnet transforma esses dispositivos em proxies para tráfego malicioso, permitindo que os atacantes anonimizem suas atividades e potencialmente lancem novos ataques.

{{< ad-banner >}}

Acredita-se que os roteadores comprometidos estejam executando firmware desatualizado com vulnerabilidades conhecidas, embora nenhum identificador CVE específico tenha sido divulgado no relatório. A infraestrutura e os métodos de propagação da botnet ainda estão sob análise, mas a escala da infecção destaca os riscos representados por dispositivos IoT sem patches.

As organizações são aconselhadas a inventariar seus dispositivos de rede, garantir que o firmware esteja atualizado e monitorar padrões de tráfego incomuns que possam indicar uso de proxy. A falta de indicadores técnicos detalhados no relatório inicial sugere que mais investigações são necessárias para desenvolver assinaturas de detecção.

{{< netrunner-insight >}}

Para analistas de SOC, este é um lembrete para monitorar conexões de saída inesperadas de dispositivos de rede, especialmente roteadores mais antigos. As equipes de DevSecOps devem aplicar políticas de atualização de firmware e considerar segmentar dispositivos IoT das redes críticas. Sem IoCs específicos, a análise de tráfego de linha de base e a impressão digital de dispositivos são fundamentais para detectar essa atividade de botnet.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
