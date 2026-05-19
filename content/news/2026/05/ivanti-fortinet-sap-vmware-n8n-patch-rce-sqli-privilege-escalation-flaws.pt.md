---
title: "Ivanti, Fortinet, SAP, VMware, n8n corrigem falhas de RCE, SQLi e escalonamento de privilégio"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "pt"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "Vários fornecedores lançam correções de segurança para vulnerabilidades críticas, incluindo Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) que pode levar à divulgação de informações ou ataques do lado do cliente."
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Vários fornecedores lançam correções de segurança para vulnerabilidades críticas, incluindo Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) que pode levar à divulgação de informações ou ataques do lado do cliente.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP e VMware lançaram patches de segurança corrigindo múltiplas vulnerabilidades que poderiam ser exploradas para bypass de autenticação e execução arbitrária de código. A falha mais crítica é a CVE-2026-8043 no Ivanti Xtraction, com pontuação CVSS 9.6, que permite controle externo de um nome de arquivo, levando à divulgação de informações ou ataques do lado do cliente.

{{< ad-banner >}}

Outros fornecedores também corrigiram problemas de alta gravidade, incluindo vulnerabilidades de injeção SQL e escalonamento de privilégio. As organizações são instadas a priorizar a correção dessas falhas, especialmente aquelas expostas à internet, pois podem ser encadeadas para comprometimento total do sistema.

Embora nenhuma exploração ativa tenha sido relatada ainda, a ampla superfície de ataque e as altas pontuações CVSS exigem atenção imediata das equipes de segurança. A varredura regular de vulnerabilidades e o gerenciamento de patches são críticos para mitigar riscos.

{{< netrunner-insight >}}

Analistas de SOC devem priorizar o patch do Ivanti Xtraction CVE-2026-8043 devido à sua pontuação CVSS crítica e potencial para ataques do lado do cliente. Equipes DevSecOps devem verificar se todos os sistemas afetados estão atualizados e monitorar quaisquer sinais de exploração, pois o controle externo de nomes de arquivo pode levar à exfiltração de dados ou movimento lateral.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
