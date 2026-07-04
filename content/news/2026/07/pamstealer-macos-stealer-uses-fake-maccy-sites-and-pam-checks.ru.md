---
title: "PamStealer — macOS-стилер, использующий поддельные сайты Maccy и проверки PAM"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "ru"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs обнаружила PamStealer — macOS-стилер информации, распространяемый через поддельные сайты Maccy и использующий проверки PAM для кражи паролей входа."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "пользователи macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs обнаружила PamStealer — macOS-стилер информации, распространяемый через поддельные сайты Maccy и использующий проверки PAM для кражи паролей входа.

{{< cyber-report severity="High" source="The Hacker News" target="пользователи macOS" >}}

Исследователи кибербезопасности из Jamf Threat Labs выявили новый стилер информации для macOS под названием PamStealer. Вредоносное ПО распространяется в виде скомпилированного файла AppleScript (.scpt), который выдает себя за Maccy — легитимный менеджер буфера обмена с открытым исходным кодом. Оно использует ряд хитрых приемов для заражения систем и кражи конфиденциальных данных, включая пароли входа.

{{< ad-banner >}}

PamStealer получил свое название из-за способности злоупотреблять фреймворком Pluggable Authentication Module (PAM) в macOS. Перехватывая процессы аутентификации, он может захватывать учетные данные пользователей при входе в систему или аутентификации для привилегированных операций. Затем стилер передает украденные данные на серверы, контролируемые злоумышленниками.

Кампания использует поддельные веб-сайты и методы социальной инженерии, чтобы обманом заставить пользователей загрузить вредоносный файл .scpt. После выполнения вредоносное ПО проводит проверки PAM для сбора паролей, не вызывая подозрений. Организациям с конечными точками macOS следует отслеживать необычные выполнения файлов .scpt и аномалии, связанные с PAM.

{{< netrunner-insight >}}

Для аналитиков SOC это подчеркивает необходимость мониторинга выполнения скомпилированных AppleScript и изменений PAM на конечных точках macOS. Команды DevSecOps должны внедрять белые списки приложений и обучать пользователей проверке источников программного обеспечения, особенно для менеджеров буфера обмена. Внедрение правил обнаружения на конечных точках для злоупотребления PAM может помочь выявить этот стилер на ранней стадии.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
