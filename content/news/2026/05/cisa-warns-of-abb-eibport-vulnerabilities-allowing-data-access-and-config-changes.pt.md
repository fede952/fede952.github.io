---
title: "CISA Alerta sobre Vulnerabilidades no ABB EIBPORT que Permitem Acesso a Dados e Alterações de Configuração"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "Dispositivos ABB EIBPORT são vulneráveis a cross-site scripting e roubo de ID de sessão. Uma atualização de firmware para a versão 3.9.2 está disponível."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "Dispositivos ABB EIBPORT"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Dispositivos ABB EIBPORT são vulneráveis a cross-site scripting e roubo de ID de sessão. Uma atualização de firmware para a versão 3.9.2 está disponível.

{{< cyber-report severity="High" source="CISA" target="Dispositivos ABB EIBPORT" cve="CVE-2021-22291" >}}

A CISA divulgou um aviso (ICSA-26-148-03) detalhando múltiplas vulnerabilidades em dispositivos ABB EIBPORT, especificamente nos modelos EIBPORT V3 KNX e EIBPORT V3 KNX GSM. As vulnerabilidades, que incluem uma falha de cross-site scripting (XSS) (CWE-79) e um problema de roubo de ID de sessão (CVE-2021-22291), poderiam permitir que um invasor acessasse informações confidenciais armazenadas no dispositivo e alterasse sua configuração.

{{< ad-banner >}}

As versões de firmware afetadas são anteriores à 3.9.2. A ABB lançou uma atualização de firmware para corrigir essas vulnerabilidades reportadas de forma privada. Os produtos são implantados mundialmente em setores críticos de manufatura e tecnologia da informação, com o fornecedor sediado na Suíça.

Embora nenhuma pontuação CVSS seja fornecida no aviso, o impacto potencial na integridade e confidencialidade do dispositivo justifica uma correção imediata. As organizações que utilizam dispositivos ABB EIBPORT afetados devem aplicar a atualização de firmware o mais rápido possível para mitigar o risco de exploração.

{{< netrunner-insight >}}

Para analistas de SOC, priorize a varredura por dispositivos ABB EIBPORT executando firmware abaixo de 3.9.2 e monitore alterações anômalas de configuração ou anomalias de sessão. As equipes de DevSecOps devem integrar esta atualização de firmware em seu pipeline de gerenciamento de patches, especialmente dado o papel do dispositivo na automação predial e infraestrutura crítica.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
