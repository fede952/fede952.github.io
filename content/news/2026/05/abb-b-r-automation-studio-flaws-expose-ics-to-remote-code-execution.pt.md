---
title: "Falhas no ABB B&R Automation Studio Expõem ICS a Execução Remota de Código"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "pt"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre 25 vulnerabilidades no ABB B&R Automation Studio, incluindo bugs críticos com CVSS 9.8 que podem permitir acesso não autorizado e execução remota de código."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre 25 vulnerabilidades no ABB B&R Automation Studio, incluindo bugs críticos com CVSS 9.8 que podem permitir acesso não autorizado e execução remota de código.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

A CISA publicou um aviso detalhando múltiplas vulnerabilidades no ABB B&R Automation Studio, afetando versões anteriores a 6.5 e a versão 6.5. O aviso lista 25 CVEs, incluindo CVE-2025-6965, CVE-2025-3277 e CVE-2023-7104, entre outras. Essas vulnerabilidades decorrem de componentes de terceiros desatualizados e incluem problemas como estouros de buffer baseados em heap, gravações fora dos limites, uso após liberação e validação de entrada inadequada.

{{< ad-banner >}}

Embora a ABB não tenha relatado exploração observada durante os testes, as vulnerabilidades podem apresentar vetores de ataque para acesso não autorizado, exposição de dados ou execução remota de código. As CVEs mais graves possuem pontuação CVSS v3 de 9,8, indicando gravidade crítica. Os produtos afetados são usados em sistemas de automação industrial e controle, tornando-os alvos atraentes para atores de ameaças.

A ABB lançou uma atualização que substitui o componente de terceiros desatualizado. As organizações que usam o B&R Automation Studio são instadas a aplicar a atualização imediatamente. Dada a natureza crítica dessas vulnerabilidades e o potencial de exploração remota, os proprietários de ativos devem priorizar a correção e monitorar quaisquer sinais de comprometimento.

{{< netrunner-insight >}}

Para analistas de SOC e engenheiros DevSecOps, este aviso ressalta o risco de dependências de terceiros em software ICS. O grande número de CVEs (25) sugere um problema sistêmico com o gerenciamento de componentes. Priorize o inventário de instâncias do B&R Automation Studio e aplique a atualização do fornecedor. Além disso, segmente as redes ICS para limitar a exposição e implemente monitoramento para comportamento anômalo que possa indicar tentativas de exploração.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
