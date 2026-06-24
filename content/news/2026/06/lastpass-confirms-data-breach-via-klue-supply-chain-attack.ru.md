---
title: "LastPass подтверждает утечку данных через атаку на цепочку поставок Klue"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "ru"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass сообщил, что злоумышленники украли OAuth-токены у стороннего приложения Klue для доступа к данным клиентов в среде Salesforce."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Среда Salesforce LastPass"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass сообщил, что злоумышленники украли OAuth-токены у стороннего приложения Klue для доступа к данным клиентов в среде Salesforce.

{{< cyber-report severity="High" source="BleepingComputer" target="Среда Salesforce LastPass" >}}

LastPass подтвердил, что хакеры получили доступ к данным клиентов из его среды Salesforce после кражи OAuth-токенов компании в ходе атаки на цепочку поставок Klue в начале этого месяца. Утечка, о которой было объявлено 23 июня 2026 года, подчеркивает риски, связанные с интеграцией сторонних приложений и кражей токенов.

{{< ad-banner >}}

Злоумышленники использовали скомпрометированные OAuth-токены от Klue, стороннего приложения, для получения несанкционированного доступа к экземпляру Salesforce LastPass. Эта атака на цепочку поставок позволила злоумышленникам выкрасть данные клиентов, не вызывая типичных оповещений об аутентификации.

LastPass уведомляет пострадавших клиентов и отозвал скомпрометированные токены. Компания также пересматривает политики доступа сторонних приложений, чтобы предотвратить подобные инциденты. Эта утечка подчеркивает важность мониторинга использования OAuth-токенов и внедрения строгих мер контроля доступа для интегрированных сервисов.

{{< netrunner-insight >}}

Этот инцидент является классическим примером риска цепочки поставок через злоупотребление OAuth-токенами. Аналитикам SOC следует уделять первоочередное внимание мониторингу аномального использования токенов и внедрять политики истечения срока действия токенов. Команды DevSecOps должны применять принцип наименьших привилегий для интеграций со сторонними приложениями и рассмотреть возможность использования краткосрочных токенов для уменьшения радиуса поражения.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
