---
title: "Vulnérabilité XSS critique dans Zimbra permet l'exécution de code via des e-mails spécialement conçus"
date: "2026-07-11T08:44:58Z"
original_date: "2026-07-11T06:45:55"
lang: "fr"
translationKey: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
slug: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Zimbra demande de mettre à jour une vulnérabilité critique de XSS stocké dans le client Web classique qui permet l'exécution de code arbitraire via des e-mails spécialement conçus."
original_url: "https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html"
source: "The Hacker News"
severity: "Critical"
target: "Client Web classique Zimbra"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Zimbra demande de mettre à jour une vulnérabilité critique de XSS stocké dans le client Web classique qui permet l'exécution de code arbitraire via des e-mails spécialement conçus.

{{< cyber-report severity="Critical" source="The Hacker News" target="Client Web classique Zimbra" >}}

Zimbra a divulgué une vulnérabilité de sécurité critique dans son client Web classique qui pourrait permettre à des attaquants d'exécuter du code arbitraire via du cross-site scripting (XSS) stocké. La faille permet à des e-mails spécialement conçus d'exécuter des scripts malveillants dans la session d'un utilisateur, pouvant conduire à une compromission totale du client de messagerie et des données associées.

{{< ad-banner >}}

La vulnérabilité, qui n'a pas encore reçu d'identifiant CVE, affecte le composant client Web classique. Zimbra exhorte tous les clients à appliquer les mises à jour disponibles immédiatement pour atténuer le risque. Aucun score CVSS n'a été fourni, mais la capacité d'exécuter du code via la livraison d'e-mails en fait un problème hautement prioritaire pour les organisations utilisant Zimbra.

En tant que vulnérabilité XSS stocké, l'attaque ne nécessite aucune interaction de l'utilisateur au-delà de l'ouverture de l'e-mail malveillant. Cela augmente la probabilité d'exploitation, en particulier dans les environnements où le filtrage des e-mails peut ne pas détecter la charge utile conçue. Les administrateurs doivent prioriser le correctif et revoir les contrôles de sécurité des e-mails.

{{< netrunner-insight >}}

Pour les analystes SOC, il s'agit d'un XSS stocké classique qui contourne les filtres de messagerie traditionnels. Les équipes DevSecOps doivent immédiatement corriger le client Web classique Zimbra et envisager de déployer des pare-feu d'applications Web avec des règles XSS. Surveillez l'exécution de scripts inhabituels dans les sessions utilisateur comme signal de détection.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html)**
