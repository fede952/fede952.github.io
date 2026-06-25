---
title: "Cordyceps CI/CD 결함, 300개 이상의 GitHub 리포지토리 위협"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "ko"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Cordyceps로 명명된 새로운 CI/CD 워크플로우 취약점으로 인해 공격자가 워크플로우를 탈취하고 주요 조직의 오픈소스 공급망을 손상시킬 수 있습니다."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "GitHub의 CI/CD 워크플로우"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Cordyceps로 명명된 새로운 CI/CD 워크플로우 취약점으로 인해 공격자가 워크플로우를 탈취하고 주요 조직의 오픈소스 공급망을 손상시킬 수 있습니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="GitHub의 CI/CD 워크플로우" >}}

Novee Security의 사이버보안 연구원들이 CI/CD 워크플로우에서 Cordyceps로 명명된 중요한 악용 가능한 패턴을 식별했습니다. 이 패턴은 공격자가 워크플로우를 탈취하고 오픈소스 공급망을 손상시킬 수 있습니다. 이 결함은 Microsoft, Google, Apache를 포함한 주요 조직의 300개 이상의 GitHub 리포지토리에 영향을 미칩니다.

{{< ad-banner >}}

Cordyceps 패턴은 리포지토리에 대한 완전한 공격자 제어를 가능하게 하여, 승인되지 않은 코드 변경, 백도어 삽입 및 다운스트림 공급망 공격으로 이어질 수 있습니다. 이 취약점은 입력을 적절히 격리하거나 검증하지 못하는 안전하지 않은 워크플로우 구성에서 비롯됩니다.

GitHub Actions 또는 유사한 CI/CD 플랫폼을 사용하는 조직은 Cordyceps 패턴에 대해 워크플로우 정의를 검토하고, 최소 권한 권한, 입력 삭제 및 환경 격리를 구현하여 위험을 완화해야 합니다.

{{< netrunner-insight >}}

이것은 전형적인 공급망 공격 벡터입니다. SOC 분석가는 비정상적인 워크플로우 실행과 예상치 못한 리포지토리 변경을 모니터링해야 합니다. DevSecOps 팀은 신뢰할 수 없는 입력 처리와 권한 범위 지정에 중점을 두고 CI/CD 파이프라인 구성을 즉시 감사해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
