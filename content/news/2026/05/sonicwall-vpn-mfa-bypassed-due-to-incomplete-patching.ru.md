---
title: "Обход MFA в SonicWall VPN из-за неполного исправления"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "ru"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "Злоумышленники подбирают учетные данные VPN и обходят MFA на неисправленных устройствах SonicWall Gen6 SSL-VPN, развертывая инструменты для программ-вымогателей."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "Устройства SonicWall Gen6 SSL-VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Злоумышленники подбирают учетные данные VPN и обходят MFA на неисправленных устройствах SonicWall Gen6 SSL-VPN, развертывая инструменты для программ-вымогателей.

{{< cyber-report severity="High" source="BleepingComputer" target="Устройства SonicWall Gen6 SSL-VPN" >}}

Наблюдается, как злоумышленники подбирают учетные данные VPN и обходят многофакторную аутентификацию (MFA) на устройствах SonicWall Gen6 SSL-VPN. Атаки используют неполное исправление, позволяя противникам развертывать инструменты, обычно используемые в операциях с программами-вымогателями.

{{< ad-banner >}}

Уязвимость позволяет злоумышленникам получить несанкционированный доступ к внутренним сетям после компрометации учетных данных VPN. Попав внутрь, они могут перемещаться по сети и развертывать полезные нагрузки программ-вымогателей, что представляет значительный риск для организаций, полагающихся на эти устройства для удаленного доступа.

SonicWall выпустила исправления для устранения проблемы, но неполное применение этих обновлений оставляет системы уязвимыми. Организациям настоятельно рекомендуется проверить, что все рекомендованные исправления полностью установлены, и отслеживать признаки несанкционированного доступа к VPN.

{{< netrunner-insight >}}

Этот инцидент подчеркивает критическую важность тщательного управления исправлениями. Аналитикам SOC следует уделить первоочередное внимание проверке того, что все устройства SonicWall Gen6 имеют последнюю прошивку, и мониторить журналы VPN на предмет аномальных шаблонов аутентификации. Командам DevSecOps следует рассмотреть внедрение дополнительных уровней MFA и сегментацию сети для смягчения таких обходов.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
