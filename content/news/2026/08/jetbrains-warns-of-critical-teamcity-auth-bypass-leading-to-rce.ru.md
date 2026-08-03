---
title: "JetBrains предупреждает о критическом обходе аутентификации в TeamCity, ведущем к удаленному выполнению кода"
date: "2026-08-03T10:38:49Z"
original_date: "2026-07-30T22:01:31"
lang: "ru"
translationKey: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
slug: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "JetBrains предупреждает о критическом обходе аутентификации в TeamCity On-Premises, который может позволить удаленное выполнение кода. Рекомендуется немедленно установить обновления."
original_url: "https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "TeamCity On-Premises"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

JetBrains предупреждает о критическом обходе аутентификации в TeamCity On-Premises, который может позволить удаленное выполнение кода. Рекомендуется немедленно установить обновления.

{{< cyber-report severity="Critical" source="BleepingComputer" target="TeamCity On-Premises" >}}

JetBrains выпустила предупреждение о критической уязвимости обхода аутентификации, затрагивающей TeamCity On-Premises. Эта ошибка может быть использована неаутентифицированным злоумышленником для достижения удаленного выполнения кода на затронутом сервере, что представляет серьезный риск для организаций, полагающихся на TeamCity для своих конвейеров сборки и непрерывной интеграции.

{{< ad-banner >}}

Уязвимость особенно тревожна, поскольку серверы TeamCity часто содержат конфиденциальный исходный код, артефакты сборки и учетные данные, что делает их привлекательными целями для злоумышленников. Успешная эксплуатация может привести к полной компрометации сервера и, возможно, более широкой инфраструктуры, если сервер не изолирован должным образом.

Организациям, использующим TeamCity On-Premises, следует немедленно установить обновления безопасности, предоставленные поставщиком. До установки обновлений рекомендуется ограничить сетевой доступ к серверу TeamCity и отслеживать любую подозрительную активность.

{{< netrunner-insight >}}

Это критическая уязвимость, которую следует рассматривать как чрезвычайную ситуацию. Аналитикам SOC следует немедленно проверить, использует ли их организация TeamCity On-Premises, и убедиться в статусе установки обновлений. Учитывая возможность неаутентифицированного удаленного выполнения кода, предполагайте компрометацию, если сервер доступен извне, и проведите тщательное криминалистическое исследование. Командам DevSecOps также следует рассмотреть возможность сегментации серверов сборки и применения строгих мер контроля доступа для уменьшения радиуса поражения.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/)**
