---
title: "Загрузчик HollowFrame и бэкдор Matryoshka нацелены на юридическую фирму"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "ru"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "Новый загрузчик на Go HollowFrame и бэкдор на Rust Matryoshka использовались в фишинговой атаке на юридическую фирму, согласно Blackpoint Cyber."
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "Юридическая фирма"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Новый загрузчик на Go HollowFrame и бэкдор на Rust Matryoshka использовались в фишинговой атаке на юридическую фирму, согласно Blackpoint Cyber.

{{< cyber-report severity="High" source="The Hacker News" target="Юридическая фирма" >}}

Blackpoint Cyber обнаружила новую цепочку атак, нацеленную на юридическую фирму, начиная с фишингового письма, которое побуждает получателя загрузить зашифрованный архив. Архив содержит файл ярлыка Windows (LNK), который при выполнении запускает многоступенчатый процесс заражения.

{{< ad-banner >}}

Атака использует два ранее неизвестных семейства вредоносных программ: HollowFrame, фреймворк загрузчика на Go, и Matryoshka, бэкдор на Rust. Загрузчик отвечает за доставку бэкдора, который предоставляет злоумышленникам удаленный доступ к скомпрометированной системе.

Эта кампания подчеркивает продолжающуюся эволюцию вредоносных инструментов: злоумышленники используют кроссплатформенные языки, такие как Go и Rust, чтобы избежать обнаружения и усложнить анализ. Использование зашифрованных архивов и LNK-файлов в фишинге является распространенной тактикой, но комбинация этих конкретных инструментов добавляет новый уровень сложности.

{{< netrunner-insight >}}

Аналитикам SOC следует уделять приоритетное внимание мониторингу выполнения LNK-файлов и загрузок архивов по ссылкам из электронных писем, так как это ранние индикаторы данной цепочки атак. Командам DevSecOps следует рассмотреть возможность блокировки или изоляции выполнения файлов из зашифрованных архивов, а также убедиться, что решения для обнаружения и реагирования на конечных точках (EDR) настроены на обнаружение бинарных файлов Go и Rust, демонстрирующих поведение загрузчика.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
