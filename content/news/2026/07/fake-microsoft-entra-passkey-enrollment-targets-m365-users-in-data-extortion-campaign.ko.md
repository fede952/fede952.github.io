---
title: "가짜 Microsoft Entra 패스키 등록, 데이터 갈취 캠페인으로 M365 사용자 표적"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "ko"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "위협 행위자 O-UNC-066이 음성 기반 피싱을 사용해 사용자를 속여 가짜 Entra 패스키를 등록하게 하며, 데이터 갈취를 위해 Microsoft 365 계정을 손상시키려 합니다."
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

위협 행위자 O-UNC-066이 음성 기반 피싱을 사용해 사용자를 속여 가짜 Entra 패스키를 등록하게 하며, 데이터 갈취를 위해 Microsoft 365 계정을 손상시키려 합니다.

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365 사용자" >}}

Okta가 O-UNC-066으로 추적하는 위협 행위자가 여러 부문의 Microsoft 365 사용자를 대상으로 음성 기반 피싱 공격을 수행하는 것이 관찰되었습니다. 공격자는 합법적인 보안 요청으로 가장하여 피해자를 속여 가짜 Entra 패스키를 등록하게 함으로써, 공격자가 계정에 무단으로 접근할 수 있도록 합니다.

{{< ad-banner >}}

이 캠페인은 패스키 등록 과정을 가로채기 위해 특별히 설계된 패널 제어 피싱 키트를 활용합니다. 공격자가 접근 권한을 얻으면 민감한 정보를 유출하고 몸값을 요구하는 데이터 갈취를 수행하려 합니다. 이러한 공격은 전통적인 이메일 기반 피싱 방어를 우회하기 위해 음성 채널을 사용하는 증가 추세를 강조합니다.

조직은 하드웨어 보안 키를 사용한 다중 인증(MFA)을 구현하고, 사용자가 원치 않는 보안 요청을 대체 통신 채널을 통해 확인하도록 교육하는 것이 좋습니다. 비정상적인 패스키 등록 활동을 모니터링하면 이러한 공격을 조기에 탐지하는 데 도움이 될 수 있습니다.

{{< netrunner-insight >}}

이 공격은 음성 기반 보안 요청을 피싱 이메일과 동일한 의심으로 대우하는 것의 중요성을 강조합니다. SOC 분석가는 비정상적인 패스키 등록 시도를 모니터링하고 MFA 등록 프로세스가 대역 외 확인을 요구하도록 해야 합니다. DevSecOps 팀은 패스키 등록을 신뢰할 수 있는 장치 및 위치로 제한하는 조건부 액세스 정책 구현을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
