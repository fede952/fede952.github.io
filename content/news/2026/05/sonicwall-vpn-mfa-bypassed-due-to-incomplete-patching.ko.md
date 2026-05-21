---
title: "SonicWall VPN MFA 우회, 불완전한 패치로 인해 발생"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "ko"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "위협 행위자들이 패치되지 않은 SonicWall Gen6 SSL-VPN 어플라이언스에서 VPN 자격 증명을 무차별 대입하고 MFA를 우회하여 랜섬웨어 도구를 배포하고 있습니다."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "SonicWall Gen6 SSL-VPN 어플라이언스"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

위협 행위자들이 패치되지 않은 SonicWall Gen6 SSL-VPN 어플라이언스에서 VPN 자격 증명을 무차별 대입하고 MFA를 우회하여 랜섬웨어 도구를 배포하고 있습니다.

{{< cyber-report severity="High" source="BleepingComputer" target="SonicWall Gen6 SSL-VPN 어플라이언스" >}}

위협 행위자들이 SonicWall Gen6 SSL-VPN 어플라이언스에서 VPN 자격 증명을 무차별 대입하고 다중 요소 인증(MFA)을 우회하는 것이 관찰되었습니다. 이 공격은 불완전한 패치를 악용하여 공격자가 랜섬웨어 작전에 일반적으로 사용되는 도구를 배포할 수 있게 합니다.

{{< ad-banner >}}

이 취약점으로 인해 공격자는 VPN 자격 증명을 탈취한 후 내부 네트워크에 무단으로 접근할 수 있습니다. 내부에 침투한 후에는 측면 이동을 통해 랜섬웨어 페이로드를 배포할 수 있어, 이러한 어플라이언스를 원격 접속에 의존하는 조직에 심각한 위험을 초래합니다.

SonicWall은 이 문제를 해결하기 위한 패치를 출시했지만, 업데이트가 불완전하게 적용되면 시스템이 노출된 상태로 남습니다. 조직은 권장되는 모든 패치가 완전히 설치되었는지 확인하고 무단 VPN 접속 징후를 모니터링할 것을 권고합니다.

{{< netrunner-insight >}}

이번 사건은 철저한 패치 관리의 중요성을 강조합니다. SOC 분석가는 모든 SonicWall Gen6 어플라이언스에 최신 펌웨어가 설치되었는지 확인하고 VPN 로그에서 비정상적인 인증 패턴을 모니터링해야 합니다. DevSecOps 팀은 추가 MFA 계층과 네트워크 분할을 구현하여 이러한 우회를 완화하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
