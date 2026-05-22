---
title: "Vulnerabilidades no ABB Terra AC Wallbox Permitem Execução Remota de Código"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "pt"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre estouros de buffer na pilha e no heap no ABB Terra AC Wallbox (JP) ≤1.8.33; atualize para 1.8.36 para mitigar CVE-2025-10504, CVE-2025-12142, CVE-2025-12143."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre estouros de buffer na pilha e no heap no ABB Terra AC Wallbox (JP) ≤1.8.33; atualize para 1.8.36 para mitigar CVE-2025-10504, CVE-2025-12142, CVE-2025-12143.

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

A ABB divulgou múltiplas vulnerabilidades que afetam sua linha de produtos Terra AC Wallbox (JP), especificamente versões até e incluindo 1.8.33. As falhas incluem um estouro de buffer baseado em heap (CVE-2025-10504), uma cópia de buffer sem verificar o tamanho da entrada (CVE-2025-12142) e um estouro de buffer baseado em pilha (CVE-2025-12143). A exploração bem-sucedida pode permitir que um atacante corrompa a memória heap, potencialmente levando ao controle remoto do dispositivo e a escritas não autorizadas na memória flash, alterando assim o comportamento do firmware.

{{< ad-banner >}}

As vulnerabilidades são avaliadas com uma pontuação base CVSS v3 de 6,1, indicando gravidade média. A ABB lançou a versão de firmware 1.8.36 para corrigir esses problemas. Os produtos são implantados mundialmente no setor de energia, e o fornecedor recomenda aplicar a atualização o mais rápido possível.

Embora nenhuma exploração ativa tenha sido relatada, o potencial para execução remota de código e manipulação de firmware torna essas vulnerabilidades críticas para operadores de infraestrutura de carregamento de veículos elétricos. As organizações devem priorizar a correção dos dispositivos afetados, especialmente aqueles expostos a redes não confiáveis.

{{< netrunner-insight >}}

Para analistas de SOC, monitore tráfego anômalo para dispositivos Terra AC Wallbox, especialmente operações inesperadas de escrita na memória flash. Engenheiros de DevSecOps devem impor validação rigorosa de entrada em quaisquer protocolos personalizados que se comuniquem com o carregador e garantir que as atualizações de firmware sejam aplicadas prontamente. Dada a pontuação CVSS de 6,1, trate estas como prioridade média, mas com alto potencial de impacto devido ao papel do dispositivo na infraestrutura crítica de energia.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
