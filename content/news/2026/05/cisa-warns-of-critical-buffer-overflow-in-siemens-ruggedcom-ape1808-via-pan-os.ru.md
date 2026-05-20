---
title: "CISA предупреждает о критическом переполнении буфера в Siemens RUGGEDCOM APE1808 через PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "ru"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Переполнение буфера в Captive Portal Palo Alto Networks PAN-OS затрагивает устройства Siemens RUGGEDCOM APE1808. CVE-2026-0300 позволяет неаутентифицированному удаленному выполнению кода с привилегиями root."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "устройства Siemens RUGGEDCOM APE1808"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Переполнение буфера в Captive Portal Palo Alto Networks PAN-OS затрагивает устройства Siemens RUGGEDCOM APE1808. CVE-2026-0300 позволяет неаутентифицированному удаленному выполнению кода с привилегиями root.

{{< cyber-report severity="Critical" source="CISA" target="устройства Siemens RUGGEDCOM APE1808" cve="CVE-2026-0300" cvss="10.0" >}}

CISA опубликовала уведомление (ICSA-26-139-02), описывающее критическую уязвимость переполнения буфера в сервисе User-ID Authentication Portal (Captive Portal) программного обеспечения Palo Alto Networks PAN-OS. Эта ошибка, отслеживаемая как CVE-2026-0300 с оценкой CVSS 10.0, позволяет неаутентифицированному злоумышленнику выполнить произвольный код с привилегиями root на межсетевых экранах серий PA и VM, отправляя специально сформированные пакеты.

{{< ad-banner >}}

Уязвимость затрагивает устройства Siemens RUGGEDCOM APE1808 всех версий. Siemens готовит исправления и рекомендует применять обходные меры, предоставленные в уведомлениях безопасности Palo Alto Networks. Пока исправления недоступны, организациям следует отключить сервис Captive Portal, если он не требуется, и ограничить сетевой доступ к затронутым устройствам.

Учитывая критическую оценку CVSS и возможность полной компрометации системы, требуются немедленные действия. Уведомление нацелено на сектор критического производства, устройства развернуты по всему миру. Операторам следует в первую очередь применить меры смягчения и отслеживать признаки эксплуатации.

{{< netrunner-insight >}}

Это классический пример риска цепочки поставок: сторонний компонент (PAN-OS) вносит критическую ошибку в промышленный продукт. Аналитикам SOC следует немедленно искать аномальный трафик к портам Captive Portal и убедиться, что сегментация ограничивает воздействие. Командам DevSecOps необходимо инвентаризировать все экземпляры RUGGEDCOM APE1808 и без промедления применить меры смягчения от Palo Alto Networks.

{{< /netrunner-insight >}}

---

**[Читать полную статью на CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
