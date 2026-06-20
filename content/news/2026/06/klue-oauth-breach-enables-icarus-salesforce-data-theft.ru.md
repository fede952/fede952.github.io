---
title: "Утечка OAuth в Klue позволяет Icarus красть данные Salesforce"
date: "2026-06-20T10:03:21Z"
original_date: "2026-06-18T14:19:50"
lang: "ru"
translationKey: "klue-oauth-breach-enables-icarus-salesforce-data-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Злоумышленники использовали утечку OAuth в Klue для кражи данных Salesforce CRM из нескольких организаций в рамках продолжающейся кампании вымогательства."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/"
source: "BleepingComputer"
severity: "High"
target: "Данные Salesforce CRM через OAuth"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Злоумышленники использовали утечку OAuth в Klue для кражи данных Salesforce CRM из нескольких организаций в рамках продолжающейся кампании вымогательства.

{{< cyber-report severity="High" source="BleepingComputer" target="Данные Salesforce CRM через OAuth" >}}

Платформа рыночной аналитики Klue пострадала от утечки OAuth, которая позволила группе злоумышленников, известной как 'Icarus', украсть данные Salesforce CRM из нескольких организаций. Атакующие использовали скомпрометированные токены OAuth для доступа и выгрузки конфиденциальных данных управления взаимоотношениями с клиентами, которые теперь используются в кампании вымогательства.

{{< ad-banner >}}

Утечка подчеркивает риски, связанные с интеграциями OAuth и сторонним доступом к критически важным бизнес-платформам. Организациям, использующим сервисы Klue, рекомендуется пересмотреть политики токенов OAuth и отслеживать несанкционированный доступ к экземплярам Salesforce.

Icarus связывают с серией атак кражи данных, нацеленных на среды Salesforce. Метод работы группы включает эксплуатацию слабых конфигураций OAuth и практик управления токенами для получения постоянного доступа к данным CRM.

{{< netrunner-insight >}}

Этот инцидент подчеркивает критическую необходимость строгого управления жизненным циклом токенов OAuth и непрерывного мониторинга сторонних интеграций. Аналитикам SOC следует уделить первоочередное внимание аудиту разрешений OAuth и внедрению обнаружения аномалий для необычных шаблонов доступа к данным из интегрированных приложений.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)**
