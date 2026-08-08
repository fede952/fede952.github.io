---
title: "AitM 피싱 캠페인, Microsoft 365를 표적으로 삼아 금융 이메일 탈취"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "ko"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "광범위한 이메일 기반 피싱이 중간자 공격(AitM)을 이용해 Microsoft 365 계정을 탈취하고, 급여 및 재무 관련 이메일을 수집하는 것을 목표로 합니다."
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365 계정"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

광범위한 이메일 기반 피싱이 중간자 공격(AitM)을 이용해 Microsoft 365 계정을 탈취하고, 급여 및 재무 관련 이메일을 수집하는 것을 목표로 합니다.

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365 계정" >}}

사이버보안 연구원들은 중간자 공격(AitM) 기법을 활용하여 Microsoft 365 계정을 손상시키는 활발하고 광범위한 이메일 기반 피싱 캠페인을 식별했습니다. 이 캠페인의 주요 목표는 재무 워크플로에 관여하는 핵심 인력을 식별하고, 특히 급여 및 재무와 관련된 이메일 통신을 외부로 유출하는 것입니다.

{{< ad-banner >}}

공격자들은 리지덴셜 프록시를 사용하여 악성 로그인을 일반 소비자 트래픽으로 위장함으로써, 일반적으로 의심스러운 IP 주소를 플래그하는 보안 제어를 회피합니다. 이 기술을 통해 공격자는 손상된 계정에 대한 지속적인 접근 권한을 유지하고 즉각적인 경보를 발생시키지 않을 수 있습니다.

Microsoft 365를 사용하는 조직은 이러한 AitM 피싱 시도에 경계해야 합니다. 이러한 공격은 자격 증명과 세션 토큰을 실시간으로 중계하여 다단계 인증을 우회하는 경우가 많습니다. 이 캠페인이 금융 데이터에 초점을 맞추고 있다는 것은 금융 사기나 비즈니스 이메일 침해(BEC)를 용이하게 하기 위한 표적 공격임을 시사합니다.

{{< netrunner-insight >}}

이 캠페인은 FIDO2 보안 키와 같은 피싱에 강한 MFA와 특히 리지덴셜 IP 범위에서 발생하는 비정상적인 로그인에 대한 지속적인 모니터링의 필요성을 강조합니다. SOC 팀은 AitM 툴킷에 대한 탐지 규칙을 우선시하고 위험 신호에 따라 접근을 제한하는 조건부 액세스 정책을 시행해야 합니다. DevSecOps 엔지니어는 세션 바인딩 및 장치 준수 검사를 구현하여 토큰 릴레이 공격을 완화하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
