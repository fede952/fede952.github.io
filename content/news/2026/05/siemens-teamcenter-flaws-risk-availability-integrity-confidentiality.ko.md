---
title: "지멘스 Teamcenter 결함, 가용성, 무결성, 기밀성 위험"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "ko"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "지멘스 Teamcenter의 여러 취약점으로 인해 가용성, 무결성 및 기밀성이 손상될 수 있습니다. 즉시 최신 버전으로 업데이트하십시오."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "지멘스 Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

지멘스 Teamcenter의 여러 취약점으로 인해 가용성, 무결성 및 기밀성이 손상될 수 있습니다. 즉시 최신 버전으로 업데이트하십시오.

{{< cyber-report severity="High" source="CISA" target="지멘스 Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

지멘스 Teamcenter는 가용성, 무결성 및 기밀성 손상으로 이어질 수 있는 여러 취약점의 영향을 받습니다. 결함에는 비정상적이거나 예외적인 조건에 대한 부적절한 확인, 크로스 사이트 스크립팅, 하드코딩된 자격 증명 사용이 포함됩니다. 영향을 받는 버전에는 Teamcenter V2312, V2406, V2412, V2506 및 V2512가 포함됩니다.

{{< ad-banner >}}

CVE-2024-4367은 PDF.js에서 글꼴을 처리할 때 유형 검사가 누락되어 PDF.js 컨텍스트에서 임의의 JavaScript 실행을 허용하는 취약점입니다. 이 취약점은 Firefox 및 Thunderbird에 영향을 미치지만 지멘스 권고에 나열되어 있습니다. 지멘스는 이러한 위험을 완화하기 위해 Teamcenter를 최신 버전으로 업데이트할 것을 권장합니다.

이 취약점의 CVSS v3 기본 점수는 7.5로 높은 심각도를 나타냅니다. 중요 제조 부문이 영향을 받으며 전 세계적으로 배포됩니다. 조직은 패치 적용을 우선시하고 이러한 취약점에 대한 노출을 검토해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 즉시 모든 Teamcenter 인스턴스를 인벤토리화하고 최신 버전으로 패치를 우선 적용해야 합니다. DevSecOps 팀은 PDF.js 구성 요소가 업데이트되었는지 확인하고 이러한 CVE를 대상으로 하는 악용 시도를 모니터링해야 합니다. 높은 CVSS 점수와 완전한 손상 가능성을 고려하여 높은 우선 순위의 수정으로 처리하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
