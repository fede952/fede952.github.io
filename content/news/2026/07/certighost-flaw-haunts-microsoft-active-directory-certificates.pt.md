---
title: "Falha 'Certighost' assombra certificados do Microsoft Active Directory"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "pt"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "A Microsoft corrigiu uma vulnerabilidade de alta gravidade que permite escalonamento de privilégios em ambientes Active Directory. Analistas de SOC devem priorizar a aplicação de patches."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Serviços de Certificado do Microsoft Active Directory"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A Microsoft corrigiu uma vulnerabilidade de alta gravidade que permite escalonamento de privilégios em ambientes Active Directory. Analistas de SOC devem priorizar a aplicação de patches.

{{< cyber-report severity="High" source="Dark Reading" target="Serviços de Certificado do Microsoft Active Directory" >}}

A Microsoft corrigiu uma vulnerabilidade de alta gravidade nos Serviços de Certificado do Active Directory, apelidada de 'Certighost', que poderia permitir que um invasor escalonasse privilégios e comprometesse um ambiente Active Directory. A falha foi divulgada pela Dark Reading em 28 de julho de 2026.

{{< ad-banner >}}

A vulnerabilidade afeta o processo de inscrição de certificados, permitindo que um agente de ameaças com acesso de baixo nível eleve seus privilégios para administrador de domínio. Isso pode levar ao comprometimento total da infraestrutura de AD, incluindo a capacidade de forjar certificados e se passar por qualquer usuário ou dispositivo.

Organizações que utilizam os Serviços de Certificado do Microsoft Active Directory são instadas a aplicar as atualizações de segurança mais recentes imediatamente. A vulnerabilidade ressalta a natureza crítica dos serviços de certificado na manutenção da confiança em ambientes de AD.

{{< netrunner-insight >}}

Este é um vetor de ataque clássico a serviços de certificado do AD. Certifique-se de que seus modelos de certificado estejam protegidos e que as permissões de inscrição sejam rigorosamente controladas. Aplique patches imediatamente e monitore solicitações de certificado incomuns ou escalonamentos de privilégio.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em Dark Reading ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
