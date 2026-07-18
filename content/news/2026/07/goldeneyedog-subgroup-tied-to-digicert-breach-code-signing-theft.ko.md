---
title: "GoldenEyeDog 하위 그룹, DigiCert 침해 및 코드 서명 도난과 연계"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "ko"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "연구원들은 2026년 4월 DigiCert 사고를 중국 사이버 범죄 그룹 GoldenEyeDog의 하위 그룹인 CylindricalCanine의 소행으로 지목했습니다. 이 그룹은 도박 및 게임 업계를 표적으로 삼는 것으로 알려져 있습니다."
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "DigiCert 코드 서명 인프라"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

연구원들은 2026년 4월 DigiCert 사고를 중국 사이버 범죄 그룹 GoldenEyeDog의 하위 그룹인 CylindricalCanine의 소행으로 지목했습니다. 이 그룹은 도박 및 게임 업계를 표적으로 삼는 것으로 알려져 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="DigiCert 코드 서명 인프라" >}}

사이버 보안 연구원들은 2026년 4월 DigiCert 보안 사고를 CylindricalCanine이라는 위협 활동 클러스터의 소행으로 규명했습니다. 이 그룹은 GoldenEyeDog(APT-Q-27, Dragon Breath, Miuuti Group으로도 알려짐)의 하위 그룹으로, 역사적으로 도박 및 게임 업계를 표적으로 삼는 중국 사이버 범죄 그룹입니다.

{{< ad-banner >}}

이 침해 사고는 코드 서명 인증서 도난을 포함하며, 이를 통해 위협 행위자가 합법적인 자격 증명으로 악성 소프트웨어에 서명하여 보안 제어를 우회할 수 있습니다. Expel은 이 사건의 기술적 세부 사항을 공유하며 작전의 정교함을 강조했습니다.

DigiCert가 발급한 인증서에 의존하는 조직은 인증서 인벤토리를 검토하고 무단 사용 여부를 모니터링해야 합니다. 이 사고는 신뢰할 수 있는 인증 기관을 대상으로 한 공급망 공격의 위험을 강조합니다.

{{< netrunner-insight >}}

SOC 분석가를 위한 조언: 코드 서명 이상 징후 및 예상치 못한 인증서 사용에 대한 모니터링을 우선시하십시오. DevSecOps 팀은 엄격한 인증서 수명 주기 관리를 시행하고, 도난으로 인한 노출을 제한하기 위해 단기 인증서 사용을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
