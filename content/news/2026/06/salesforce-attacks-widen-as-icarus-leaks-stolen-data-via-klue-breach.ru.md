---
title: "Атаки на Salesforce расширяются: Icarus утекает украденные данные через взлом Klue"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "ru"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "Злоумышленники использовали OAuth-токены Klue для доступа к экземплярам Salesforce; появляются новые жертвы, поскольку Icarus публикует украденные данные."
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Экземпляры Salesforce через OAuth-токены Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Злоумышленники использовали OAuth-токены Klue для доступа к экземплярам Salesforce; появляются новые жертвы, поскольку Icarus публикует украденные данные.

{{< cyber-report severity="High" source="Dark Reading" target="Экземпляры Salesforce через OAuth-токены Klue" >}}

Масштаб продолжающихся атак на Salesforce расширился: угрозы, отслеживаемые как Icarus, утекают данные, украденные у нескольких жертв. Злоумышленники первоначально взломали поставщика приложений Klue и использовали его OAuth-токены для получения несанкционированного доступа к средам Salesforce клиентов.

{{< ad-banner >}}

Согласно Dark Reading, после первоначального раскрытия появились новые жертвы, что указывает на то, что кампания атак шире, чем предполагалось ранее. Использование OAuth-токенов позволило злоумышленникам обойти традиционные механизмы аутентификации и напрямую получить доступ к данным Salesforce, не вызывая типичных оповещений.

Организации, использующие интеграции Salesforce со сторонними поставщиками, такими как Klue, призывают провести аудит разрешений OAuth-токенов и отслеживать аномальные шаблоны доступа. Группа Icarus начала публиковать украденные данные, что повышает срочность реагирования для пострадавших компаний.

{{< netrunner-insight >}}

Эта атака подчеркивает риск злоупотребления OAuth-токенами в экосистемах SaaS. Аналитикам SOC следует уделять первоочередное внимание мониторингу необычных вызовов API и использования токенов от интегрированных сторонних приложений. Команды DevSecOps должны внедрять строгое управление жизненным циклом токенов и применять разрешения по принципу «точно в срок», чтобы ограничить радиус поражения.

{{< /netrunner-insight >}}

---

**[Читать полную статью на Dark Reading ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
