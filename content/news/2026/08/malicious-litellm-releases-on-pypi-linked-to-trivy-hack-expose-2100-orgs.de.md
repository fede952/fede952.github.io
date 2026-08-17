---
title: "Bösartige LiteLLM-Veröffentlichungen auf PyPI im Zusammenhang mit Trivy-Hack legen über 2.100 Organisationen offen"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "de"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "Zwei bösartige LiteLLM-Pakete auf PyPI stahlen Cloud-Schlüssel, SSH-Schlüssel und mehr. CloudSEK-Daten deuten darauf hin, dass über 2.100 Organisationen betroffen sein könnten."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "LiteLLM-Nutzer auf PyPI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Zwei bösartige LiteLLM-Pakete auf PyPI stahlen Cloud-Schlüssel, SSH-Schlüssel und mehr. CloudSEK-Daten deuten darauf hin, dass über 2.100 Organisationen betroffen sein könnten.

{{< cyber-report severity="High" source="The Hacker News" target="LiteLLM-Nutzer auf PyPI" >}}

Zwei bösartige LiteLLM-Versionen wurden im März auf PyPI veröffentlicht und blieben etwa 40 Minuten lang verfügbar. Diese Pakete enthielten Code zum Stehlen von Anmeldeinformationen, der darauf ausgelegt war, eine breite Palette von Geheimnissen zu sammeln, darunter Cloud-Zugriffsschlüssel, private SSH-Schlüssel, Kubernetes-Tokens und Datenbankpasswörter von jedem System, das sie installierte.

{{< ad-banner >}}

Das Threat-Intelligence-Unternehmen CloudSEK erhielt einen Datensatz, der aus etwa 434.000 Dateien besteht, die die Angreifer erbeutet hatten. Die Analyse dieses Datensatzes legt nahe, dass die Offenlegung mehr als 2.100 Organisationen betreffen könnte, was das potenzielle Ausmaß des Kompromisses verdeutlicht.

Der Vorfall steht im Zusammenhang mit dem früheren Trivy-Hack und deutet auf einen koordinierten Supply-Chain-Angriff hin. Organisationen, die LiteLLM während des betroffenen Zeitraums von PyPI installiert haben, sollten sofort alle offengelegten Anmeldeinformationen rotieren und nach Anzeichen für unbefugten Zugriff suchen.

{{< netrunner-insight >}}

Dieser Vorfall unterstreicht die kritische Notwendigkeit von Wachsamkeit in der Software-Lieferkette. SOC-Analysten sollten Installationen der bösartigen LiteLLM-Versionen überwachen und die Rotation von Anmeldeinformationen für potenziell offengelegte Geheimnisse priorisieren. DevSecOps-Teams sollten strenge Paketintegritätsprüfungen durchsetzen und die Verwendung von privaten Spiegeln oder Sperrdateien mit Hashes in Betracht ziehen, um solche Risiken zu mindern.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
