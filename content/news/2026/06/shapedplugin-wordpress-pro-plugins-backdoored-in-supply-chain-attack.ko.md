---
title: "ShapedPlugin WordPress 프로 플러그인, 공급망 공격으로 백도어 삽입"
date: "2026-06-23T10:30:52Z"
original_date: "2026-06-22T18:00:48"
lang: "ko"
translationKey: "shapedplugin-wordpress-pro-plugins-backdoored-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "여러 ShapedPlugin WordPress 프로 플러그인이 공급망 공격을 통해 손상되어 공식 릴리스에 백도어 코드가 주입되었습니다."
original_url: "https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html"
source: "The Hacker News"
severity: "High"
target: "ShapedPlugin의 WordPress 프로 플러그인"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

여러 ShapedPlugin WordPress 프로 플러그인이 공급망 공격을 통해 손상되어 공식 릴리스에 백도어 코드가 주입되었습니다.

{{< cyber-report severity="High" source="The Hacker News" target="ShapedPlugin의 WordPress 프로 플러그인" >}}

ShapedPlugin의 여러 WordPress 플러그인이 공급망 공격으로 손상되었습니다. 알려지지 않은 위협 행위자가 공식 릴리스 채널을 변조하고 백도어 코드를 푸시했습니다. Wordfence에 따르면, 공격자는 공급업체의 빌드 및 배포 파이프라인을 손상시켜 공식 라이선스 업데이트 채널을 통해 배포되는 프로 플러그인 릴리스에 백도어 코드를 주입했습니다.

{{< ad-banner >}}

이번 공격은 단일 손상된 공급업체가 수많은 웹사이트에 영향을 미칠 수 있는 타사 플러그인 생태계와 관련된 위험을 강조합니다. ShapedPlugin 프로 플러그인 사용자는 설치 무결성을 확인하고 가능한 경우 최신 패치 버전으로 업데이트하는 것이 좋습니다.

Wordfence는 손상된 설치를 탐지하는 데 사용할 수 있는 백도어 코드에 대한 상세 분석을 발표했습니다. 조직은 WordPress 환경에서 무단 액세스 또는 악성 활동의 징후가 있는지 검토해야 합니다.

{{< netrunner-insight >}}

이번 공급망 공격은 소프트웨어 공급망 보안 통제의 중요성을 강조합니다. SOC 분석가는 비정상적인 플러그인 업데이트 동작을 모니터링하고 모든 타사 코드에 대한 무결성 검사를 구현하는 것을 고려해야 합니다. DevSecOps 팀은 유사한 손상을 방지하기 위해 엄격한 파이프라인 보안 및 코드 서명을 시행해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html)**
