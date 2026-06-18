---
title: "CISA, Rockwell FactoryTalk Analytics PavilionX의 중요 인증 우회 경고"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 Rockwell Automation FactoryTalk Analytics PavilionX <7.01에 영향을 미치는 CVE-2025-14272에 대해 경고하며, 중요 제조 환경에서 권한 없는 특권 작업을 허용할 수 있습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 Rockwell Automation FactoryTalk Analytics PavilionX <7.01에 영향을 미치는 CVE-2025-14272에 대해 경고하며, 중요 제조 환경에서 권한 없는 특권 작업을 허용할 수 있습니다.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA는 Rockwell Automation FactoryTalk Analytics PavilionX의 인증 누락 취약점에 대한 권고(ICSA-26-167-01)를 발표했습니다. CVE-2025-14272로 추적되는 이 결함은 7.01 이전 버전에 영향을 미치며, 인증되지 않은 공격자가 사용자 및 역할 관리와 같은 특권 작업을 실행할 수 있게 합니다.

{{< ad-banner >}}

이 취약점은 API 엔드포인트에서 부적절한 인증 시행으로 인해 발생합니다. 성공적인 악용은 영향을 받는 시스템에 대한 완전한 관리 제어로 이어질 수 있습니다. Rockwell Automation은 이 문제를 해결하기 위해 버전 7.01을 출시했으며, 사용자는 즉시 업그레이드할 것을 권장합니다.

이 제품이 전 세계 중요 제조 분야에 배포되어 있기 때문에 운영 중단이나 데이터 손상의 위험이 상당합니다. 조직은 패치 적용을 우선시하고 액세스 제어를 검토하여 잠재적인 악용을 완화해야 합니다.

{{< netrunner-insight >}}

이는 높은 우선순위로 패치해야 하는 전형적인 인증 우회입니다. SOC 분석가는 PavilionX 환경에서 비정상적인 API 호출이나 권한 상승을 모니터링해야 합니다. DevSecOps 팀은 버전 7.01이 배포되고 네트워크 분할이 이러한 엔드포인트의 노출을 제한하는지 확인해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
