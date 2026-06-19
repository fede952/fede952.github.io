---
title: "DragonForce, Microsoft Teams 릴레이를 이용해 백도어.Turn C2 트래픽을 은닉하다"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "ko"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForce 랜섬웨어 그룹이 맞춤형 Go 기반 RAT인 Backdoor.Turn을 배포하여 Microsoft Teams 릴레이 내에 C2 트래픽을 숨기고, 주요 미국 서비스 기업을 표적으로 삼았습니다."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "주요 미국 서비스 기업"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForce 랜섬웨어 그룹이 맞춤형 Go 기반 RAT인 Backdoor.Turn을 배포하여 Microsoft Teams 릴레이 내에 C2 트래픽을 숨기고, 주요 미국 서비스 기업을 표적으로 삼았습니다.

{{< cyber-report severity="High" source="The Hacker News" target="주요 미국 서비스 기업" >}}

DragonForce 랜섬웨어 그룹과 연계된 위협 행위자들이 맞춤형 Go 기반 원격 접근 트로이목마(RAT)인 Backdoor.Turn을 사용하여 명령 및 제어(C2) 트래픽을 Microsoft Teams 릴레이 인프라 내에 은닉하는 것이 관찰되었습니다. 이 백도어는 Broadcom 소유의 Symantec과 Carbon Black의 조사 결과에 따르면 주요 미국 서비스 기업을 대상으로 배포되었습니다.

{{< ad-banner >}}

합법적인 Microsoft Teams 릴레이를 활용함으로써 공격자는 악성 트래픽을 정상적인 비즈니스 통신과 혼합하여 네트워크 방어자가 탐지하기 더 어렵게 만듭니다. Go 기반 RAT는 공격자에게 지속적인 접근 권한과 명령 실행, 데이터 유출, 추가 페이로드 배포 능력을 제공합니다.

이 기법은 랜섬웨어 그룹이 전통적인 네트워크 모니터링 도구를 회피하기 위해 진화하는 전술을 강조합니다. Microsoft Teams를 사용하는 조직은 보안 구성을 검토하고 비정상적인 릴레이 트래픽 패턴을 모니터링해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 비정상적인 Microsoft Teams 릴레이 트래픽, 특히 비표준 엔드포인트나 업무 시간 외의 트래픽을 모니터링해야 합니다. DevSecOps 팀은 엄격한 애플리케이션 허용 목록을 적용하고 Teams 트래픽에서 C2 통신을 나타낼 수 있는 암호화된 터널을 검사해야 합니다. 이 공격은 신뢰할 수 있는 협업 플랫폼에서도 제로 트러스트 원칙의 필요성을 강조합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
