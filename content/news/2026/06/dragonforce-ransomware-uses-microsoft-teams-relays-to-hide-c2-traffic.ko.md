---
title: "DragonForce 랜섬웨어, Microsoft Teams 릴레이를 사용해 C2 트래픽 은닉"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "ko"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForce 랜섬웨어가 맞춤형 악성코드 'Backdoor.Turn'을 배포하여 Microsoft Teams 릴레이 인프라 내에서 명령 및 제어(C2) 트래픽을 숨깁니다."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Teams 릴레이 인프라"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForce 랜섬웨어가 맞춤형 악성코드 'Backdoor.Turn'을 배포하여 Microsoft Teams 릴레이 인프라 내에서 명령 및 제어(C2) 트래픽을 숨깁니다.

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Teams 릴레이 인프라" >}}

DragonForce 랜섬웨어 그룹이 'Backdoor.Turn'이라는 맞춤형 악성코드를 사용하여 Microsoft Teams 릴레이 인프라 내에서 명령 및 제어(C2) 트래픽을 숨기는 것이 관찰되었습니다. 이 기술을 통해 공격자는 악성 통신을 합법적인 Teams 트래픽과 혼합하여 네트워크 방어자가 탐지하기 어렵게 만듭니다.

{{< ad-banner >}}

Microsoft Teams 릴레이를 남용함으로써 랜섬웨어 갱은 신뢰할 수 있는 서비스로의 트래픽을 면밀히 조사하지 않을 수 있는 기존 네트워크 보안 제어를 우회할 수 있습니다. 악성코드는 Teams API 또는 프로토콜을 활용하여 C2 데이터를 터널링하고, 시그니처 기반 탐지를 회피하며 손상된 네트워크에 지속적인 접근을 허용할 가능성이 있습니다.

Microsoft Teams를 사용하는 조직은 Teams 엔드포인트로의 비정상적인 아웃바운드 트래픽 패턴을 모니터링하고 암호화된 터널에 대한 추가 검사를 구현하는 것을 고려해야 합니다. 이 사건은 랜섬웨어 그룹이 탐지를 회피하기 위해 living-off-the-land 및 신뢰 서비스 남용 기술을 채택하는 증가하는 추세를 강조합니다.

{{< netrunner-insight >}}

SOC 분석가에게 이는 정상적인 Teams 트래픽을 기준으로 삼고 예상치 못한 데이터 볼륨이나 비표준 Teams 엔드포인트로의 연결과 같은 이상 징후에 대해 경고해야 함을 강조합니다. DevSecOps 팀은 Teams 통합 권한을 검토하고 불필요한 API 액세스를 제한하여 릴레이 남용을 위한 공격 표면을 줄여야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
