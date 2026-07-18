---
title: "새로운 wp2shell WordPress 코어 결함으로 인증되지 않은 공격자가 코드 실행 가능"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "ko"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "익명의 HTTP 요청으로 WordPress 사이트에서 코드를 실행할 수 있습니다. 이 버그는 코어에 영향을 미치므로 기본 설치도 취약합니다. 패치가 적용될 때까지 모든 6.9 및 7.0 사이트가 위험에 노출되었습니다."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPress 코어 (버전 6.9 및 7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

익명의 HTTP 요청으로 WordPress 사이트에서 코드를 실행할 수 있습니다. 이 버그는 코어에 영향을 미치므로 기본 설치도 취약합니다. 패치가 적용될 때까지 모든 6.9 및 7.0 사이트가 위험에 노출되었습니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPress 코어 (버전 6.9 및 7.0)" >}}

WordPress 코어에서 인증되지 않은 원격 코드 실행 취약점이 발견되어 버전 6.9 및 7.0에 영향을 미칩니다. wp2shell로 명명된 이 결함은 공격자가 특수하게 조작된 HTTP 요청을 보내 대상 사이트에서 임의의 코드를 실행할 수 있게 합니다. 특히 이 취약점은 코어 소프트웨어에 존재하므로 플러그인이 없는 새로운 WordPress 설치도 취약합니다.

{{< ad-banner >}}

전체 기술 세부 정보와 작동하는 개념 증명이 게시되었으며, 두 가지 기본 결함에 CVE 식별자가 할당되었습니다. 또한 지속적인 객체 캐시 조건이 확인되어 특정 환경에서 악용을 복잡하게 만들 수 있습니다. 영향을 받는 버전을 실행하는 모든 사이트는 패치가 적용될 때까지 위험한 것으로 간주되었습니다.

관리자는 즉시 최신 패치 버전으로 업데이트해야 합니다. 악용의 용이성과 WordPress의 광범위한 사용을 고려할 때 이 취약점은 웹 보안에 심각한 위협이 됩니다. 조직은 패치를 최우선으로 하고 웹 애플리케이션 방화벽 규칙을 검토하여 악용 시도를 탐지하고 차단해야 합니다.

{{< netrunner-insight >}}

이것은 코어 소프트웨어가 인증되지 않은 공격에 대해 강화되어야 하는 이유를 보여주는 전형적인 사례입니다. SOC 분석가는 즉시 WordPress 6.9 및 7.0 인스턴스를 스캔하고 패치 상태를 확인해야 합니다. DevSecOps 팀은 이번 사례를 통해 런타임 애플리케이션 자체 보호(RASP)를 구현하고 wp-admin 또는 wp-includes를 대상으로 하는 비정상적인 HTTP 요청을 모니터링해야 한다는 점을 상기해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
