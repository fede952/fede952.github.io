---
title: "Ботнет Popa связан с израильской фирмой Alarum Technologies"
date: "2026-07-13T10:19:43Z"
original_date: "2026-06-18T17:37:58"
lang: "ru"
translationKey: "popa-botnet-tied-to-israeli-firm-alarum-technologies"
slug: "popa-botnet-tied-to-israeli-firm-alarum-technologies"
author: "NewsBot (Validated by Federico Sella)"
description: "Исследователи связывают ботнет Popa на базе Android с NetNut, сервисом резидентных прокси, принадлежащим публично торгуемой компании Alarum Technologies, используемым для мошенничества с рекламой и взлома учетных записей."
original_url: "https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/"
source: "Krebs on Security"
severity: "High"
target: "Android TV boxes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Исследователи связывают ботнет Popa на базе Android с NetNut, сервисом резидентных прокси, принадлежащим публично торгуемой компании Alarum Technologies, используемым для мошенничества с рекламой и взлома учетных записей.

{{< cyber-report severity="High" source="Krebs on Security" target="Android TV boxes" >}}

За последние четыре года ботнет Popa заразил миллионы Android-телевизионных приставок, используя их для ретрансляции вредоносного трафика с целью мошенничества с рекламой, взлома учетных записей и сбора данных. Инфраструктура ботнета опирается на резидентные прокси для сокрытия своей деятельности.

{{< ad-banner >}}

На этой неделе несколько компаний по кибербезопасности пришли к выводу, что Popa связан с NetNut, провайдером резидентных прокси, управляемым Alarum Technologies Ltd, публично торгуемой израильской компанией. Эта связь предполагает, что коммерческий сервис мог быть сознательно или неосознанно использован для киберпреступных операций.

Масштаб ботнета, затрагивающий миллионы устройств, подчеркивает растущую угрозу ботнетов на базе IoT и Android. Вовлечение публично торгуемой компании ставит вопросы о корпоративной ответственности и надзоре в индустрии прокси-сервисов.

{{< netrunner-insight >}}

Аналитикам SOC следует отслеживать трафик с диапазонов IP-адресов резидентных прокси, связанных с NetNut, так как они могут указывать на активность ботнета Popa. Командам DevSecOps следует обеспечить сегментацию устройств IoT и их регулярное обновление для предотвращения подобных заражений. Этот случай подчеркивает необходимость должной осмотрительности при интеграции сторонних прокси-сервисов в архитектуры безопасности.

{{< /netrunner-insight >}}

---

**[Читать полную статью на Krebs on Security ›](https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/)**
