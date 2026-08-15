---
title: "Sandworm 연계 UAC-0145, 가짜 면접을 이용해 악성 VPN 유포"
date: "2026-08-15T07:23:49Z"
original_date: "2026-08-11T18:36:47"
lang: "ko"
translationKey: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
slug: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-UA는 러시아 국가 후원 위협 행위자가 가짜 면접을 통해 우크라이나 IT 종사자를 표적으로 삼아 명령 실행이 가능한 VPN을 전달한다고 경고했습니다."
original_url: "https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html"
source: "The Hacker News"
severity: "High"
target: "우크라이나 IT 종사자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-UA는 러시아 국가 후원 위협 행위자가 가짜 면접을 통해 우크라이나 IT 종사자를 표적으로 삼아 명령 실행이 가능한 VPN을 전달한다고 경고했습니다.

{{< cyber-report severity="High" source="The Hacker News" target="우크라이나 IT 종사자" >}}

CERT-UA는 러시아 국가 후원 그룹 Sandworm(APT44)의 하위 그룹인 위협 클러스터 UAC-0145로 attributed되는 새로운 사회 공학 캠페인을 공개했습니다. 이 캠페인은 채용 담당자를 사칭하고 가짜 면접으로 유인하여 우크라이나의 IT 종사자를 표적으로 삼습니다.

{{< ad-banner >}}

면접 과정에서 피해자는 임의 명령을 실행할 수 있는 악성 코드인 VPN 애플리케이션을 설치하도록 속임을 당합니다. 이 기술은 채용에 대한 신뢰를 악용하여 사용자 방어를 우회합니다.

이 활동은 우크라이나 조직, 특히 IT 부문에 대한 러시아 국가 후원 행위자의 지속적인 사이버 위협을 강조합니다. CERT-UA의 UAC-0145 귀속은 이러한 공격의 정교하고 지속적인 특성을 강조합니다.

{{< netrunner-insight >}}

이 캠페인은 보안에 민감한 IT 전문가에게도 악성 코드를 전달하는 사회 공학의 효과를 보여줍니다. SOC 분석가는 사용자에게 이러한 채용 기반 미끼에 대해 교육하고 비정상적인 VPN 설치 또는 명령 실행을 모니터링해야 합니다. DevSecOps 팀은 애플리케이션 허용 목록을 적용하고 서명되지 않은 바이너리 실행을 제한하여 이러한 위협을 완화해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)**
