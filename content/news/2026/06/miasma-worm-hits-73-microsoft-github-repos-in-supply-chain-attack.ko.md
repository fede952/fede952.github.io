---
title: "미아즈마 웜, 공급망 공격으로 마이크로소프트 GitHub 저장소 73개 감염"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "ko"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "마이크로소프트의 Azure, Azure-Samples, Microsoft, MicrosoftDocs 조직에 속한 GitHub 저장소가 미아즈마(Miasma) 자가 복제 웜에 의해 손상되어 73개 저장소가 영향을 받았습니다."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "마이크로소프트 GitHub 저장소"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

마이크로소프트의 Azure, Azure-Samples, Microsoft, MicrosoftDocs 조직에 속한 GitHub 저장소가 미아즈마(Miasma) 자가 복제 웜에 의해 손상되어 73개 저장소가 영향을 받았습니다.

{{< cyber-report severity="High" source="The Hacker News" target="마이크로소프트 GitHub 저장소" >}}

미아즈마 자가 복제 공급망 공격 캠페인이 마이크로소프트의 GitHub 저장소로 확대되어 Azure, Azure-Samples, Microsoft, MicrosoftDocs 등 4개 조직의 73개 저장소가 손상되었습니다. 이 사건은 OpenSourceMalware에 의해 보고되었으며, GitHub는 확산을 차단하기 위해 영향을 받은 저장소에 대한 접근을 차단했습니다.

{{< ad-banner >}}

이번 공격은 소프트웨어 공급망에서 자가 복제 멀웨어의 위협이 증가하고 있음을 강조합니다. 신뢰할 수 있는 저장소가 손상되면 공격자는 이러한 소스를 의존하는 다운스트림 프로젝트에 악성 코드를 주입하여 광범위한 사용자와 조직에 영향을 미칠 수 있습니다.

손상의 구체적인 기술적 세부 사항은 공개되지 않았지만, 이번 사건은 CI/CD 파이프라인 및 저장소 관리에서 강화된 보안 조치의 필요성을 강조합니다. 조직은 마이크로소프트 GitHub 저장소에 대한 의존성을 검토하고 비정상적인 활동을 모니터링해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 자신의 GitHub 조직에서 비정상적인 커밋이나 접근 패턴을 모니터링하는 데 우선순위를 두어야 합니다. DevSecOps 팀은 엄격한 브랜치 보호 규칙을 적용하고, 서명된 커밋을 요구하며, CI/CD 파이프라인에서 자가 복제 멀웨어에 대한 자동 스캔을 구현해야 합니다. 이번 사건은 마이크로소프트와 같은 주요 벤더도 공급망 공격으로부터 안전하지 않다는 것을 상기시켜 줍니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
