---
title: "Утечка в репозитории CISA на GitHub раскрыла ключи AWS GovCloud на шесть месяцев"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "ru"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "Подрядчик случайно опубликовал внутренние учетные данные CISA, включая ключи AWS GovCloud, на GitHub на шесть месяцев. Эксперты выделяют критические уроки для команд безопасности."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "Репозиторий CISA на GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Подрядчик случайно опубликовал внутренние учетные данные CISA, включая ключи AWS GovCloud, на GitHub на шесть месяцев. Эксперты выделяют критические уроки для команд безопасности.

{{< cyber-report severity="High" source="Krebs on Security" target="Репозиторий CISA на GitHub" >}}

Агентство по кибербезопасности и защите инфраструктуры (CISA) раскрыло утечку данных, в ходе которой подрядчик случайно опубликовал десятки внутренних учетных данных, включая ключи AWS GovCloud, в публичном репозитории GitHub. Учетные данные оставались открытыми почти шесть месяцев, пока KrebsOnSecurity не уведомил агентство.

{{< ad-banner >}}

Разбор CISA выявил пробелы в первоначальном реагировании, такие как задержка обнаружения и отсутствие автоматического сканирования секретов в публичных репозиториях. Инцидент подчеркивает необходимость надежного управления секретами и непрерывного мониторинга репозиториев кода.

Эксперты рекомендуют внедрять pre-commit хуки, регулярное сканирование секретов и строгий контроль доступа для предотвращения подобных утечек. Использование эфемерных учетных данных и автоматическая ротация также могут смягчить последствия раскрытия ключей.

{{< netrunner-insight >}}

Этот инцидент — классический пример того, почему сканирование секретов должно быть интегрировано в CI/CD пайплайны, а не только после коммита. Аналитикам SOC следует уделять приоритетное внимание оповещениям о раскрытии публичных репозиториев, а команды DevSecOps должны обеспечивать минимальные привилегии для подрядчиков. Автоматизируйте ротацию учетных данных и рассмотрите использование таких инструментов, как GitLeaks или TruffleHog, для раннего обнаружения утечек.

{{< /netrunner-insight >}}

---

**[Читать полную статью на Krebs on Security ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
