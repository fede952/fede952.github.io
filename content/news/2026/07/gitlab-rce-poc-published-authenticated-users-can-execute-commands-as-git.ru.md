---
title: "Опубликован PoC эксплуатации RCE в GitLab: аутентифицированные пользователи могут выполнять команды от имени git"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "ru"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "Опубликован proof-of-concept эксплойт для уязвимости удаленного выполнения кода в GitLab, нацеленный на неисправленные серверы self-managed версии 18.11.3. Аутентифицированные пользователи могут выполнять команды от имени пользователя git."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab self-managed 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Опубликован proof-of-concept эксплойт для уязвимости удаленного выполнения кода в GitLab, нацеленный на неисправленные серверы self-managed версии 18.11.3. Аутентифицированные пользователи могут выполнять команды от имени пользователя git.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab self-managed 18.11.3" >}}

24 июля 2026 года исследователи безопасности из depthfirst опубликовали рабочий proof-of-concept эксплойт для уязвимости удаленного выполнения кода в GitLab. Эта уязвимость, которую GitLab исправил 10 июня 2026 года, позволяет любому аутентифицированному пользователю с правами на отправку изменений в проект выполнять произвольные команды от имени пользователя git на серверах self-managed GitLab 18.11.3, которые не применили обновление.

{{< ad-banner >}}

Эксплойт использует специально созданный блокнот Jupyter, добавленный в проект. Когда атакующий открывает diff коммита, вредоносный блокнот вызывает утечку кучи, что позволяет выполнять команды. Этот метод обходит типичные средства контроля аутентификации и не требует особых привилегий, кроме стандартного доступа к проекту.

Организации, использующие self-managed экземпляры GitLab, должны немедленно проверить, что они применили патч от 10 июня. Публичная доступность кода эксплойта увеличивает риск активной эксплуатации, особенно для экземпляров, доступных из интернета. Синим командам следует отслеживать необычные коммиты блокнотов Jupyter и неожиданную активность пользователя git.

{{< netrunner-insight >}}

Этот эксплойт подчеркивает опасность задержки с установкой патчей в self-managed CI/CD платформах. Аналитикам SOC следует уделить приоритетное внимание обнаружению аномальных процессов пользователя git и неожиданных загрузок блокнотов Jupyter. DevSecOps команды должны установить строгий срок установки патчей для GitLab и рассмотреть сегментацию сети для ограничения доступа к self-managed экземплярам.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
