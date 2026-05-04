---
title: "Ruby Gems 및 Go 모듈의 슬리퍼 패키지가 CI/CD 파이프라인을 표적으로 삼다"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "ko"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "공격자들은 슬리퍼 패키지를 사용하여 악성 페이로드를 전달하고, 자격 증명을 탈취하며, GitHub Actions를 변조하고, 소프트웨어 공급망 공격에서 SSH 지속성을 확립합니다."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "CI/CD 파이프라인 및 소프트웨어 공급망"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

공격자들은 슬리퍼 패키지를 사용하여 악성 페이로드를 전달하고, 자격 증명을 탈취하며, GitHub Actions를 변조하고, 소프트웨어 공급망 공격에서 SSH 지속성을 확립합니다.

{{< cyber-report severity="High" source="The Hacker News" target="CI/CD 파이프라인 및 소프트웨어 공급망" >}}

새로운 소프트웨어 공급망 공격 캠페인이 관찰되었으며, 슬리퍼 패키지를 통로로 사용하여 이후에 자격 증명 탈취, GitHub Actions 변조, SSH 지속성을 가능하게 하는 악성 페이로드를 푸시합니다. 이 활동은 "BufferZoneCorp"라는 GitHub 계정에 기인하며, 이 계정은 악성 Ruby gems 및 Go 모듈과 관련된 저장소 세트를 게시했습니다.

{{< ad-banner >}}

이 공격은 처음에는 양호해 보이는 패키지를 사용하다가 나중에 악성 업데이트를 받는 기법, 즉 "슬리퍼" 또는 "트로이 목마화된" 패키지로 알려진 기법을 활용합니다. CI/CD 환경에 설치되면 페이로드가 자격 증명을 탈취하고, GitHub Actions 워크플로를 수정하며, 지속적인 SSH 액세스를 설정하여 개발 파이프라인에 심각한 위협을 제기합니다.

신뢰할 수 없는 소스의 Ruby gems 또는 Go 모듈을 사용하는 조직은 종속성을 감사하고 의심스러운 저장소 활동을 모니터링해야 합니다. 이 캠페인은 개발자 인프라를 표적으로 하는 공급망 공격의 진화하는 정교함을 강조합니다.

{{< netrunner-insight >}}

이 캠페인은 CI/CD 파이프라인에서 엄격한 종속성 고정 및 무결성 검증의 필요성을 강조합니다. SOC 분석가는 비정상적인 GitHub Actions 수정 및 SSH 키 추가를 모니터링해야 하며, DevSecOps 엔지니어는 최소 권한 액세스를 구현하고 폭발 반경을 제한하기 위해 임시 빌드 환경 사용을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
