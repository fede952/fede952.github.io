---
title: "MITRE ATT&CK v19 Overhauls Defense Evasion with New Tactics"
date: "2026-06-23T10:34:05Z"
original_date: "2026-06-23T10:14:50"
lang: "en"
translationKey: "mitre-att-ck-v19-overhauls-defense-evasion-with-new-tactics"
author: "NewsBot (Validated by Federico Sella)"
description: "MITRE ATT&CK v19 introduces structural changes, deprecating Defense Evasion (TA0005) and adding Stealthee and Impair Defenses. A migration guide is provided."
original_url: "https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/"
source: "Cybersecurity360"
severity: "Info"
target: "MITRE ATT&CK framework users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

MITRE ATT&CK v19 introduces structural changes, deprecating Defense Evasion (TA0005) and adding Stealthee and Impair Defenses. A migration guide is provided.

{{< cyber-report severity="Info" source="Cybersecurity360" target="MITRE ATT&CK framework users" >}}

MITRE has released version 19 of the ATT&CK framework, introducing significant structural modifications. The most notable change is the deprecation of the Defense Evasion tactic (TA0005), which is being replaced by two new tactics: Stealthee and Impair Defenses. This restructuring aims to provide more granular categorization of adversary behaviors related to avoiding detection and disrupting defenses.

{{< ad-banner >}}

The update includes a migration guide to help organizations transition their threat models and detection rules from the old tactic to the new ones. Practitioners are advised to review their current mappings to Defense Evasion and reassign techniques to the appropriate new tactics to maintain coverage.

While no specific CVEs or vulnerabilities are associated with this release, the framework update has implications for SOC operations and threat hunting. Teams should update their MITRE ATT&CK references and adjust analytics that rely on the deprecated tactic ID.

{{< netrunner-insight >}}

For SOC analysts, this means updating your detection rules and threat hunting queries that reference TA0005. DevSecOps engineers should review CI/CD pipeline security mappings to ensure they align with the new tactics. The migration guide is essential to avoid gaps in coverage during the transition.

{{< /netrunner-insight >}}

---

**[Read full article on Cybersecurity360 ›](https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/)**
