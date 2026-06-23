---
title: "MITRE ATT&CK v19 перерабатывает уклонение от защиты с новыми тактиками"
date: "2026-06-23T10:34:05Z"
original_date: "2026-06-23T10:14:50"
lang: "ru"
translationKey: "mitre-att-ck-v19-overhauls-defense-evasion-with-new-tactics"
author: "NewsBot (Validated by Federico Sella)"
description: "MITRE ATT&CK v19 вводит структурные изменения, устаревая тактику уклонения от защиты (TA0005) и добавляя Stealthee и Impair Defenses. Предоставлено руководство по миграции."
original_url: "https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/"
source: "Cybersecurity360"
severity: "Info"
target: "пользователи фреймворка MITRE ATT&CK"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

MITRE ATT&CK v19 вводит структурные изменения, устаревая тактику уклонения от защиты (TA0005) и добавляя Stealthee и Impair Defenses. Предоставлено руководство по миграции.

{{< cyber-report severity="Info" source="Cybersecurity360" target="пользователи фреймворка MITRE ATT&CK" >}}

MITRE выпустила версию 19 фреймворка ATT&CK, вносящую значительные структурные изменения. Наиболее заметным изменением является устаревание тактики уклонения от защиты (TA0005), которая заменяется двумя новыми тактиками: Stealthee и Impair Defenses. Эта реструктуризация направлена на обеспечение более детальной категоризации поведения злоумышленников, связанного с избеганием обнаружения и нарушением защиты.

{{< ad-banner >}}

Обновление включает руководство по миграции, помогающее организациям перевести свои модели угроз и правила обнаружения со старой тактики на новые. Практикам рекомендуется пересмотреть текущие сопоставления с тактикой уклонения от защиты и переназначить техники на соответствующие новые тактики для сохранения покрытия.

Хотя с этим выпуском не связано конкретных CVE или уязвимостей, обновление фреймворка имеет последствия для операций SOC и охоты за угрозами. Команды должны обновить свои ссылки на MITRE ATT&CK и скорректировать аналитику, использующую устаревший идентификатор тактики.

{{< netrunner-insight >}}

Для аналитиков SOC это означает обновление правил обнаружения и запросов охоты за угрозами, которые ссылаются на TA0005. Инженеры DevSecOps должны пересмотреть сопоставления безопасности конвейеров CI/CD, чтобы убедиться, что они соответствуют новым тактикам. Руководство по миграции необходимо для предотвращения пробелов в покрытии во время перехода.

{{< /netrunner-insight >}}

---

**[Читать полную статью на Cybersecurity360 ›](https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/)**
