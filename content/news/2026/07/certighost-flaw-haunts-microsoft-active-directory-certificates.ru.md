---
title: "Уязвимость 'Certighost' преследует сертификаты Microsoft Active Directory"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "ru"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft исправила уязвимость высокой степени серьезности, позволяющую повышать привилегии в средах Active Directory. Аналитикам SOC следует уделить первоочередное внимание установке обновлений."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Службы сертификации Microsoft Active Directory"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft исправила уязвимость высокой степени серьезности, позволяющую повышать привилегии в средах Active Directory. Аналитикам SOC следует уделить первоочередное внимание установке обновлений.

{{< cyber-report severity="High" source="Dark Reading" target="Службы сертификации Microsoft Active Directory" >}}

Microsoft исправила уязвимость высокой степени серьезности в службах сертификации Active Directory, получившую название 'Certighost', которая может позволить злоумышленнику повысить привилегии и скомпрометировать среду Active Directory. Ошибка была раскрыта изданием Dark Reading 28 июля 2026 года.

{{< ad-banner >}}

Уязвимость затрагивает процесс регистрации сертификатов, позволяя злоумышленнику с низким уровнем доступа повысить свои привилегии до администратора домена. Это может привести к полной компрометации инфраструктуры AD, включая возможность подделки сертификатов и выдачи себя за любого пользователя или устройство.

Организации, использующие службы сертификации Microsoft Active Directory, настоятельно призываются немедленно установить последние обновления безопасности. Уязвимость подчеркивает критическую важность служб сертификации для поддержания доверия в средах AD.

{{< netrunner-insight >}}

Это классический вектор атаки на службы сертификации AD. Убедитесь, что ваши шаблоны сертификатов защищены, а разрешения на регистрацию строго контролируются. Немедленно установите обновления и отслеживайте необычные запросы сертификатов или повышения привилегий.

{{< /netrunner-insight >}}

---

**[Читать полную статью на Dark Reading ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
