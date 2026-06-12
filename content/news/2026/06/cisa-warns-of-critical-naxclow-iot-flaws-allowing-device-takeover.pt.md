---
title: "CISA Alerta sobre Falhas Críticas no IoT Naxclow que Permitem Assunção de Dispositivos"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiplas vulnerabilidades na plataforma IoT Naxclow, incluindo CVE-2026-42947, permitem sequestro de dispositivos e roubo de credenciais. Afeta campainhas inteligentes e hubs domésticos."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Dispositivos da plataforma IoT Naxclow"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiplas vulnerabilidades na plataforma IoT Naxclow, incluindo CVE-2026-42947, permitem sequestro de dispositivos e roubo de credenciais. Afeta campainhas inteligentes e hubs domésticos.

{{< cyber-report severity="Critical" source="CISA" target="Dispositivos da plataforma IoT Naxclow" cve="CVE-2026-42947" cvss="9.8" >}}

A CISA emitiu um aviso (ICSA-26-162-02) detalhando múltiplas vulnerabilidades na plataforma IoT Naxclow, afetando produtos como Smart Doorbell X3, X Smart Home, V720 e ix cam. A falha mais grave, CVE-2026-42947, possui pontuação CVSS 9.8 e envolve uma bypass de autorização através de uma chave controlada pelo usuário, permitindo que um invasor repita uma sequência de confirmar-vincular para reatribuir silenciosamente um dispositivo a uma conta arbitrária sem interação do usuário.

{{< ad-banner >}}

Fraquezas adicionais incluem verificações de autorização ausentes, uso de chaves criptográficas fixas, geração de identificadores previsíveis e inserção de informações sensíveis em arquivos acessíveis externamente. A exploração bem-sucedida pode permitir personificação de dispositivos, interceptação ou manipulação de comunicações, roubo em larga escala de credenciais e acesso não autorizado a sistemas afetados.

As vulnerabilidades afetam todas as versões dos produtos listados, e os dispositivos são implantados mundialmente em instalações comerciais. A Naxclow, sediada na China, ainda não lançou patches. Organizações que usam esses dispositivos devem implementar imediatamente segmentação de rede e monitoramento para detectar atividades anômalas de vinculação de dispositivos.

{{< netrunner-insight >}}

Este é um pesadelo clássico de IoT na cadeia de suprimentos: chaves fixas, IDs previsíveis e um fluxo de integração repetível. As equipes de SOC devem procurar por reatribuições inesperadas de dispositivos nos logs e considerar isolar os dispositivos Naxclow em uma VLAN separada até que os patches cheguem. O DevSecOps deve pressionar por identidade criptográfica de dispositivos e autenticação mútua na integração de IoT.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
