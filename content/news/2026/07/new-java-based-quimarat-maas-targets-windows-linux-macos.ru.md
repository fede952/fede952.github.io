---
title: "Новый Java-троян QuimaRAT по модели MaaS нацелен на Windows, Linux и macOS"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "ru"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT — кроссплатформенный Java-троян, продаваемый как вредоносное ПО как услуга, угрожает системам Windows, Linux и macOS. Исследователи из LevelBlue описывают его подписную модель и возможности."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "системы Windows, Linux и macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT — кроссплатформенный Java-троян, продаваемый как вредоносное ПО как услуга, угрожает системам Windows, Linux и macOS. Исследователи из LevelBlue описывают его подписную модель и возможности.

{{< cyber-report severity="High" source="The Hacker News" target="системы Windows, Linux и macOS" >}}

Исследователи в области кибербезопасности из LevelBlue выявили новый Java-троян удаленного доступа (RAT) под названием QuimaRAT, способный атаковать среды Windows, Linux и macOS. Вредоносное ПО предлагается по модели «вредоносное ПО как услуга» (MaaS) с уровнями подписки от 150 долларов за один месяц до 1200 долларов за пожизненный доступ, а также тарифом в 300 долларов.

{{< ad-banner >}}

Кроссплатформенность QuimaRAT, обеспеченная Java, позволяет ему компрометировать различные операционные системы, что делает его универсальной угрозой для организаций с неоднородными средами. Модель MaaS снижает порог входа для менее квалифицированных злоумышленников, потенциально увеличивая частоту атак.

Хотя конкретные технические детали о возможностях QuimaRAT в первоначальном отчете ограничены, его архитектура на Java предполагает, что он может использовать распространенные методы, такие как кейлоггинг, захват экрана и эксфильтрация файлов. Организациям следует отслеживать подозрительные процессы Java и внедрять разрешительные списки приложений для снижения риска.

{{< netrunner-insight >}}

Для аналитиков SOC кроссплатформенность QuimaRAT означает, что правила обнаружения должны охватывать конечные точки Windows, Linux и macOS. Командам DevSecOps следует пересмотреть использование среды выполнения Java и рассмотреть возможность ограничения выполнения неподписанных Java-приложений. Учитывая модель MaaS, ожидайте, что малоквалифицированные злоумышленники будут развертывать этот троян, поэтому критически важно базовое мониторинг необычных сетевых подключений и поведения процессов.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
