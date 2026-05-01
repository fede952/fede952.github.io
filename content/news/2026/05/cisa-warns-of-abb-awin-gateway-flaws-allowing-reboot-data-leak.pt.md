---
title: "CISA Alerta sobre Falhas em Gateways ABB AWIN que Permitem Reinicialização e Vazamento de Dados"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "Gateways ABB AWIN possuem vulnerabilidades que permitem a atacantes reiniciar dispositivos ou extrair configuração do sistema. O aviso da CISA ICSA-26-120-05 detalha a CVE-2025-13777 e correções."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "Gateways ABB AWIN"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Gateways ABB AWIN possuem vulnerabilidades que permitem a atacantes reiniciar dispositivos ou extrair configuração do sistema. O aviso da CISA ICSA-26-120-05 detalha a CVE-2025-13777 e correções.

{{< cyber-report severity="High" source="CISA" target="Gateways ABB AWIN" cve="CVE-2025-13777" cvss="8.3" >}}

A CISA publicou o aviso ICSA-26-120-05 detalhando múltiplas vulnerabilidades em gateways ABB AWIN. As falhas, que incluem bypass de autenticação por captura e repetição e ausência de autenticação para funções críticas, poderiam permitir que um atacante não autenticado reinicie remotamente o dispositivo ou consulte dados sensíveis de configuração do sistema. As vulnerabilidades afetam as versões de firmware AWIN 2.0-0, 2.0-1, 1.2-0 e 1.2-1 executadas em hardware GW100 rev.2 e GW120.

{{< ad-banner >}}

O problema mais grave, registrado como CVE-2025-13777, permite que uma consulta não autenticada revele a configuração do sistema, incluindo detalhes sensíveis. O aviso atribui uma pontuação base CVSS v3 de 8,3, indicando alta gravidade. A ABB lançou a versão de firmware 2.1-0 para o GW100 rev.2 para corrigir essas vulnerabilidades. As organizações que utilizam gateways afetados são instadas a aplicar a atualização imediatamente.

As vulnerabilidades impactam ativos do setor de manufatura crítica implantados em todo o mundo. Dado o potencial de exploração remota sem autenticação, essas falhas representam um risco significativo para ambientes de tecnologia operacional. A CISA recomenda que os usuários revisem o aviso completo e implementem mitigações, incluindo segmentação de rede e restrição de acesso aos dispositivos afetados.

{{< netrunner-insight >}}

Para analistas de SOC: monitore reinicializações não autorizadas ou consultas incomuns a gateways ABB; estes são indicadores de baixo ruído de exploração. As equipes de DevSecOps devem priorizar a atualização para o firmware 2.1-0 e aplicar controles rigorosos de acesso à rede, pois as vulnerabilidades não exigem autenticação e podem ser exploradas remotamente.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
