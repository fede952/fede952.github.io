---
title: "Falhas no Subnet Solutions PowerSYSTEM Center Permitem Vazamento de Informações e Injeção CRLF"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "pt"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre múltiplas vulnerabilidades no Subnet Solutions PowerSYSTEM Center, incluindo divulgação de informações e injeção CRLF, afetando versões de 2020 a 2026."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre múltiplas vulnerabilidades no Subnet Solutions PowerSYSTEM Center, incluindo divulgação de informações e injeção CRLF, afetando versões de 2020 a 2026.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

A CISA divulgou um aviso (ICSA-26-132-02) detalhando múltiplas vulnerabilidades no Subnet Solutions PowerSYSTEM Center, uma plataforma usada nos setores de manufatura crítica e energia. As falhas incluem autorização incorreta (CVE-2026-26289) que permite que usuários autenticados com permissões limitadas exportem contas de dispositivos e exponham informações sensíveis normalmente restritas a administradores. Além disso, vulnerabilidades de injeção CRLF (CVE-2026-35504, CVE-2026-33570, CVE-2026-35555) podem permitir que invasores injetem cabeçalhos ou respostas maliciosas.

{{< ad-banner >}}

As versões afetadas abrangem PowerSYSTEM Center 2020 (5.8.x a 5.28.x), 2024 (6.0.x a 6.1.x) e 2026 (7.0.x). As vulnerabilidades têm uma pontuação base CVSS v3 de 8,2, indicando alta gravidade. A exploração bem-sucedida pode levar à divulgação de informações e potencial manipulação de sessão ou divisão de resposta HTTP.

Devido à implantação do produto em infraestruturas críticas em todo o mundo, as organizações devem priorizar a correção. A Subnet Solutions provavelmente lançou atualizações; recomenda-se que os administradores consultem os avisos de segurança do fornecedor e apliquem os patches mais recentes. Até lá, restrinja o acesso de rede ao PowerSYSTEM Center e monitore atividades anômalas.

{{< netrunner-insight >}}

Para analistas de SOC, monitore logs de autenticação em busca de exportações incomuns de contas de dispositivos — este é um sinal revelador de exploração do CVE-2026-26289. As equipes de DevSecOps devem inventariar imediatamente as versões do PowerSYSTEM Center e aplicar patches, pois os vetores de injeção CRLF (CVE-2026-35504 e outros) podem ser encadeados com outros ataques para comprometer a integridade da sessão. Trate isso como uma remediação de alta prioridade, dada a pontuação CVSS 8.2 e a exposição em setores críticos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
