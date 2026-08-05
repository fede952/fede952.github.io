---
title: "CISA ajoute les failles Langflow RCE, Tomcat et N-central au catalogue KEV"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "fr"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "La CISA signale trois vulnérabilités activement exploitées, dont Langflow RCE (CVE-2026-9198) avec un score CVSS de 9,8, exhortant à une mise à jour immédiate."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

La CISA signale trois vulnérabilités activement exploitées, dont Langflow RCE (CVE-2026-9198) avec un score CVSS de 9,8, exhortant à une mise à jour immédiate.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

L'Agence américaine de cybersécurité et de sécurité des infrastructures (CISA) a ajouté trois vulnérabilités à son catalogue de vulnérabilités connues et exploitées (KEV), citant des preuves d'exploitation active. Parmi elles figure CVE-2026-9198, une faille critique d'injection de code dans Langflow qui permet à des attaquants non authentifiés d'exécuter du code à distance. Cette vulnérabilité présente un score CVSS de 9,8, indiquant un risque sévère.

{{< ad-banner >}}

Les deux autres failles affectent Apache Tomcat et N-central, bien que les détails spécifiques ne soient pas fournis dans le résumé. Le catalogue KEV de la CISA est une liste prioritaire de vulnérabilités connues pour être exploitées, et les agences fédérales sont tenues de les corriger dans des délais spécifiés. Les organisations sont invitées à consulter le catalogue et à appliquer les correctifs immédiatement.

L'inclusion de ces vulnérabilités souligne l'importance d'une gestion rapide des correctifs et de l'intelligence des menaces. Les équipes de sécurité doivent surveiller les indicateurs de compromission liés à ces CVE et s'assurer que leurs actifs ne sont pas exposés à des vecteurs d'attaque connus.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez la surveillance des tentatives d'exploitation contre Langflow, Tomcat et N-central, car ce sont désormais des cibles actives confirmées. Les équipes DevSecOps doivent accélérer l'application des correctifs, en particulier pour les instances exposées à Internet, et envisager d'ajouter des règles de détection supplémentaires pour l'activité post-exploitation. Compte tenu du score CVSS critique, traitez CVE-2026-9198 comme un risque de premier ordre et vérifiez qu'aucun accès non autorisé n'a eu lieu.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
