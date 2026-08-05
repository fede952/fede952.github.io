---
title: "CISA добавляет уязвимости Langflow RCE, Tomcat и N-central в каталог KEV"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "ru"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA отмечает три активно эксплуатируемые уязвимости, включая Langflow RCE (CVE-2026-9198) с CVSS 9.8, и настоятельно рекомендует немедленно установить исправления."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA отмечает три активно эксплуатируемые уязвимости, включая Langflow RCE (CVE-2026-9198) с CVSS 9.8, и настоятельно рекомендует немедленно установить исправления.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

Агентство по кибербезопасности и защите инфраструктуры США (CISA) добавило три уязвимости в свой каталог Known Exploited Vulnerabilities (KEV), ссылаясь на доказательства активной эксплуатации. Среди них CVE-2026-9198 — критическая ошибка внедрения кода в Langflow, которая позволяет неаутентифицированным злоумышленникам добиться полного удаленного выполнения кода. Уязвимость имеет оценку CVSS 9.8, что указывает на серьезный риск.

{{< ad-banner >}}

Две другие ошибки затрагивают Apache Tomcat и N-central, хотя конкретные детали в сводке не приводятся. Каталог KEV от CISA — это приоритетный список уязвимостей, о которых известно, что они эксплуатируются, и федеральные агентства обязаны устранить их в установленные сроки. Организациям настоятельно рекомендуется ознакомиться с каталогом и немедленно применить исправления.

Включение этих уязвимостей подчеркивает важность своевременного управления исправлениями и разведки угроз. Группам безопасности следует отслеживать индикаторы компрометации, связанные с этими CVE, и убедиться, что их активы не подвержены известным векторам атак.

{{< netrunner-insight >}}

Для аналитиков SOC: уделите приоритетное внимание мониторингу попыток эксплуатации Langflow, Tomcat и N-central, поскольку теперь это подтвержденные активные цели. DevSecOps следует ускорить установку исправлений, особенно для экземпляров, доступных из интернета, и рассмотреть возможность внедрения дополнительных правил обнаружения для действий после эксплуатации. Учитывая критическую оценку CVSS, относитесь к CVE-2026-9198 как к риску высшего уровня и проверьте, не было ли несанкционированного доступа.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
