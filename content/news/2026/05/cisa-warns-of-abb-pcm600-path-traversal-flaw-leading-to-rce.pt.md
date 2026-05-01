---
title: "CISA Alerta sobre Falha de Path Traversal no ABB PCM600 que Leva a RCE"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "As versões 1.5 a 2.13 do ABB PCM600 são vulneráveis a uma falha de path traversal (CVE-2018-1002208) que pode permitir execução arbitrária de código. Atualize para a versão 2.14."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

As versões 1.5 a 2.13 do ABB PCM600 são vulneráveis a uma falha de path traversal (CVE-2018-1002208) que pode permitir execução arbitrária de código. Atualize para a versão 2.14.

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

A CISA emitiu um aviso (ICSA-26-120-02) detalhando uma vulnerabilidade no ABB PCM600, um gerenciador de IED de proteção e controle. A falha, identificada como CVE-2018-1002208, existe na biblioteca SharpZip.dll e envolve a limitação inadequada de um caminho para um diretório restrito (path traversal). A exploração bem-sucedida pode permitir que um invasor envie mensagens especialmente criadas para o nó do sistema, resultando em execução arbitrária de código.

{{< ad-banner >}}

As versões afetadas do produto são PCM600 de 1.5 até e incluindo 2.13. A ABB lançou a versão 2.14 para corrigir o problema. No entanto, observe que os relés de proteção RE_630 não são compatíveis com o PCM600 2.14, portanto, os usuários de versões anteriores com RE_630 devem contar com defesas em nível de sistema, conforme descrito nas Recomendações Gerais de Segurança da ABB.

O aviso destaca que o produto é implantado mundialmente no setor de Manufatura Crítica. Embora nenhuma pontuação CVSS seja fornecida no aviso, o potencial da vulnerabilidade para execução de código justifica a aplicação imediata de patches sempre que possível. As organizações devem priorizar a atualização para o PCM600 2.14 e implementar segmentação de rede e controles de acesso para sistemas que não podem ser atualizados imediatamente.

{{< netrunner-insight >}}

Esta vulnerabilidade de path traversal no ABB PCM600 é um lembrete de que dependências legadas como SharpZip.dll podem introduzir riscos. Para analistas de SOC, monitore o tráfego de rede anômalo para nós PCM600, especialmente mensagens criadas que possam indicar tentativas de exploração. Engenheiros de DevSecOps devem inventariar todas as instâncias do PCM600 e planejar atualizações para a versão 2.14, garantindo que a compatibilidade com relés RE_630 seja tratada por meio de controles compensatórios.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
