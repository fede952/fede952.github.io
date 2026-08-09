---
title: "Установщики TrueConf получили бэкдор в результате атаки на цепочку поставок Head Mare"
date: "2026-08-09T07:48:35Z"
original_date: "2026-08-08T14:16:23"
lang: "ru"
translationKey: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
slug: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Head Mare эксплуатирует необновленные серверы TrueConf, чтобы заменить клиентские установщики на версии с бэкдором, доставляя вредоносное ПО жертвам."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/"
source: "BleepingComputer"
severity: "High"
target: "Серверы видеоконференций TrueConf"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Head Mare эксплуатирует необновленные серверы TrueConf, чтобы заменить клиентские установщики на версии с бэкдором, доставляя вредоносное ПО жертвам.

{{< cyber-report severity="High" source="BleepingComputer" target="Серверы видеоконференций TrueConf" >}}

Хактивистская группа Head Mare активно эксплуатирует уязвимости в необновленных серверах видеоконференций TrueConf. Компрометируя эти серверы, злоумышленники заменяют легитимные клиентские установщики на вредоносные версии, содержащие бэкдоры.

{{< ad-banner >}}

Когда пользователи загружают и запускают троянизированные установщики, бэкдоры развертываются на их системах, потенциально предоставляя злоумышленникам удаленный доступ и контроль. Эта атака типа «цепочка поставок» использует доверие пользователей к официальным каналам распространения программного обеспечения.

Организации, использующие TrueConf, должны немедленно проверить целостность своих установщиков и убедиться, что все серверы обновлены с учетом известных уязвимостей. Атака подчеркивает важность мониторинга необычного поведения в распространении программного обеспечения и поддержания надежных методов управления исправлениями.

{{< netrunner-insight >}}

Этот инцидент подчеркивает необходимость бдительности в отношении цепочки поставок: всегда проверяйте контрольные суммы и подписи загружаемых установщиков, даже из официальных источников. Для команд SOC: отслеживайте аномальные сетевые подключения или процессы после установки, которые могут указывать на активацию бэкдора. Управление исправлениями критически важно — необновленные серверы являются легкой добычей для злоумышленников.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/)**
