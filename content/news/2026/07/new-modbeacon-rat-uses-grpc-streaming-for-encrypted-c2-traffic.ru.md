---
title: "Новый троян MODBEACON использует gRPC-стриминг для шифрованного C2-трафика"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "ru"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Связанная с Китаем группа Silver Fox развертывает Rust-троян MODBEACON через SEO-отравление, используя gRPC-стриминг для шифрованной связи с C2."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "Пользователи Windows через поддельные установщики"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Связанная с Китаем группа Silver Fox развертывает Rust-троян MODBEACON через SEO-отравление, используя gRPC-стриминг для шифрованной связи с C2.

{{< cyber-report severity="High" source="The Hacker News" target="Пользователи Windows через поддельные установщики" >}}

Связанная с Китаем киберпреступная группа Silver Fox была идентифицирована как источник нового Rust-трояна удаленного доступа (RAT) под названием MODBEACON. Вредоносное ПО использует gRPC-стриминг для шифрованного трафика управления и контроля (C2), что усложняет его обнаружение.

{{< ad-banner >}}

По данным китайской компании по кибербезопасности QiAnXin, Silver Fox распространяет MODBEACON через поддельные установщики с использованием методов SEO-отравления. Хотя группа может выглядеть как операция с низкой сложностью и высокой активностью, их реальные организационные возможности более продвинуты.

Использование gRPC-стриминга для связи с C2 представляет собой новую технику для вредоносного ПО, так как она использует HTTP/2 и буферы протоколов для слияния с легитимным трафиком. Специалистам по безопасности следует отслеживать необычный gRPC-трафик и проверять сайты загрузки, отравленные SEO.

{{< netrunner-insight >}}

Аналитикам SOC следует добавить анализ gRPC-трафика в свои конвейеры обнаружения, так как использование MODBEACON потоковых RPC может обходить традиционные сетевые сигнатуры. Команды DevSecOps должны проверять целостность загрузок программного обеспечения и рассмотреть возможность блокировки известных доменов SEO-отравления. Этот RAT подчеркивает необходимость проактивного поиска угроз, связанных с вредоносным ПО на Rust.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
