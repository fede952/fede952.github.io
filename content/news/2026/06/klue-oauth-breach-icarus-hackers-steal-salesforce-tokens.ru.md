---
title: "Утечка OAuth в Klue: Хакеры Icarus похитили токены Salesforce"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "ru"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue подтверждает кражу токенов OAuth, затрагивающую интеграции Salesforce; группа вымогателей Icarus берет на себя ответственность, список жертв растет."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "платформа маркетинговой разведки Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue подтверждает кражу токенов OAuth, затрагивающую интеграции Salesforce; группа вымогателей Icarus берет на себя ответственность, список жертв растет.

{{< cyber-report severity="High" source="BleepingComputer" target="платформа маркетинговой разведки Klue" >}}

Платформа маркетинговой разведки Klue подтвердила инцидент безопасности, в ходе которого злоумышленники похитили токены OAuth, используемые для подключения к средам Salesforce клиентов. Утечка, за которую взяла ответственность недавно появившаяся группа вымогателей «Icarus», привела к расширению списка пострадавших.

{{< ad-banner >}}

Похищенные токены OAuth могут позволить злоумышленникам получать доступ к данным Salesforce без дополнительной аутентификации, что представляет значительный риск для клиентов Klue. Инцидент подчеркивает опасности раскрытия токенов OAuth и необходимость надежного управления их жизненным циклом.

Поскольку группа Icarus публично заявляет об атаке, организациям, использующим интеграцию Klue с Salesforce, следует немедленно отозвать и заменить все связанные токены OAuth, а также отслеживать несанкционированный доступ. Полный масштаб утечки остается предметом расследования.

{{< netrunner-insight >}}

Этот инцидент подчеркивает критическую важность защиты токенов OAuth как конфиденциальных учетных данных. Аналитикам SOC следует уделять первоочередное внимание мониторингу подозрительных вызовов API Salesforce и внедрять политики истечения срока действия токенов. Команды DevSecOps должны внедрять строгие механизмы ограничения области действия и ротации токенов, чтобы минимизировать радиус поражения в случае компрометации.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
