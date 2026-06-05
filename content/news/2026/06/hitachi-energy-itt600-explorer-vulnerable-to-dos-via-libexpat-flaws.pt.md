---
title: "Hitachi Energy ITT600 Explorer Vulnerável a DoS devido a falhas no libexpat"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "pt"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta para duas vulnerabilidades no Hitachi Energy ITT600 Explorer que podem permitir ataques de negação de serviço. Afeta versões anteriores a 2.1 SP6."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta para duas vulnerabilidades no Hitachi Energy ITT600 Explorer que podem permitir ataques de negação de serviço. Afeta versões anteriores a 2.1 SP6.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

A Hitachi Energy divulgou vulnerabilidades em seu produto ITT600 Explorer, afetando especificamente versões anteriores a 2.1 SP6. As falhas, identificadas como CVE-2024-8176 e CVE-2025-59375, envolvem recursão descontrolada e alocação de recursos sem limites ou limitação. Esses problemas podem ser explorados para causar uma condição de negação de serviço (DoS).

{{< ad-banner >}}

As vulnerabilidades residem na biblioteca libexpat usada pela funcionalidade IEC61850. Um atacante com acesso local pode enviar uma mensagem IEC61850 manipulada para desencadear um estouro de pilha, potencialmente levando à corrupção de memória além do DoS. Importante, apenas o produto ITT600 Explorer é afetado; os endpoints do sistema IEC 61850 permanecem inalterados.

A CISA recomenda ação imediata para aplicar mitigações ou atualizações. O produto é implantado mundialmente no setor de energia, e a exploração pode interromper operações de infraestrutura crítica. Organizações que usam versões afetadas devem priorizar a correção e revisar o aviso para etapas detalhadas de remediação.

{{< netrunner-insight >}}

Para analistas de SOC, monitore padrões incomuns de tráfego IEC61850 que possam indicar tentativas de exploração. Equipes de DevSecOps devem priorizar a atualização do ITT600 Explorer para a versão 2.1 SP6 ou posterior, e considerar segmentação de rede para limitar o acesso local à ferramenta. Dado o score CVSS de 7.5 e o potencial de corrupção de memória, trate isso como um patch de alta prioridade.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
