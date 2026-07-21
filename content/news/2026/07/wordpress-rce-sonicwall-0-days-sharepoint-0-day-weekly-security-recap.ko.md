---
title: "WordPress RCE, SonicWall 0-Day, SharePoint 0-Day: 주간 보안 요약"
date: "2026-07-21T09:25:16Z"
original_date: "2026-07-20T13:32:26"
lang: "ko"
translationKey: "wordpress-rce-sonicwall-0-days-sharepoint-0-day-weekly-security-recap"
slug: "wordpress-rce-sonicwall-0-days-sharepoint-0-day-weekly-security-recap"
author: "NewsBot (Validated by Federico Sella)"
description: "이번 주 위협에는 WordPress RCE, SonicWall 0-Day, AI 서비스 공격, SharePoint 0-Day가 포함됩니다. 작은 입력이 코드 실행, 메모리 손실, 키 탈취로 이어집니다."
original_url: "https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPress, SonicWall, SharePoint, AI 서비스"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

이번 주 위협에는 WordPress RCE, SonicWall 0-Day, AI 서비스 공격, SharePoint 0-Day가 포함됩니다. 작은 입력이 코드 실행, 메모리 손실, 키 탈취로 이어집니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPress, SonicWall, SharePoint, AI 서비스" >}}

이번 주 보안 환경은 널리 사용되는 플랫폼에 영향을 미치는 여러 중요한 취약점으로 특징지어집니다. WordPress 원격 코드 실행(RCE) 결함, SonicWall 제로데이, SharePoint 0-Day가 활발히 악용되거나 공개되었습니다. 공격자는 노출된 시스템, 취약한 입력 검증, 오래된 드라이버와 같은 간단한 공격 벡터를 활용하여 코드 실행, 메모리 손상, 자격 증명 탈취를 달성하고 있습니다.

{{< ad-banner >}}

전통적인 소프트웨어 취약점 외에도 AI 서비스가 공격을 받고 있으며, 공격자는 가짜 프롬프트와 공개 코드 저장소를 사용하여 악성코드를 유포하고 있습니다. 공통점은 작고 무해해 보이는 입력이 보안 도구 비활성화나 암호화 키 유출과 같은 파괴적인 결과를 초래할 수 있다는 것입니다.

방어자는 특히 알려진 익스플로잇 활동이 있는 취약점에 대한 패치 적용을 최우선으로 해야 합니다. SonicWall과 SharePoint 결함은 엔터프라이즈 환경에서의 광범위한 배포로 인해 특히 우려됩니다. 조직은 AI 서비스의 노출을 검토하고 엄격한 입력 검증 및 접근 제어를 시행해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 즉시 이러한 취약점과 관련된 침해 지표, 특히 비정상적인 아웃바운드 연결이나 프로세스 메모리 덤프를 확인해야 합니다. DevSecOps 팀은 AI 서비스 API에 대해 최소 권한을 적용하고 런타임 보안 모니터링을 구현하여 작고 악의적인 입력으로 인한 비정상적인 행동을 탐지해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html)**
