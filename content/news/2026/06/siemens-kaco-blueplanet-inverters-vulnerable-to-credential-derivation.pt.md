---
title: "Inversores Siemens KACO Blueplanet Vulneráveis à Derivação de Credenciais"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "pt"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiplas vulnerabilidades em inversores KACO blueplanet permitem que atacantes derivem credenciais a partir de números de série, obtendo acesso não autorizado. A Siemens recomenda atualizações."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Inversores Siemens KACO Blueplanet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiplas vulnerabilidades em inversores KACO blueplanet permitem que atacantes derivem credenciais a partir de números de série, obtendo acesso não autorizado. A Siemens recomenda atualizações.

{{< cyber-report severity="High" source="CISA" target="Inversores Siemens KACO Blueplanet" >}}

A CISA publicou um aviso (ICSA-26-160-02) detalhando múltiplas vulnerabilidades nos inversores Siemens KACO blueplanet. Essas falhas podem permitir que um atacante derive credenciais a partir do número de série de um dispositivo e as utilize indevidamente para obter acesso não autorizado ao inversor.

{{< ad-banner >}}

O aviso abrange uma ampla gama de modelos afetados, incluindo blueplanet 100 NX3 M8, 100 TL3 GEN2, 105 TL3 e muitos outros, com versões listadas como all/* ou versões de firmware específicas abaixo de 6.1.4.9. A KACO new energy GmbH lançou atualizações para alguns produtos e está preparando correções para outros, recomendando contramedidas onde patches ainda não estão disponíveis.

Nenhum identificador CVE ou pontuação CVSS é fornecido no aviso. As vulnerabilidades são consideradas graves devido ao potencial de exploração remota levando a acesso não autorizado ao dispositivo, o que pode impactar a infraestrutura de energia solar.

{{< netrunner-insight >}}

Para analistas de SOC e engenheiros DevSecOps, este aviso ressalta o risco de credenciais fixas ou deriváveis em dispositivos IoT/OT. Imediatamente faça o inventário dos inversores KACO afetados e aplique atualizações de firmware onde disponíveis. Para unidades não corrigidas, implemente segmentação de rede e monitore tentativas de acesso anômalas como mitigações provisórias.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
