---
title: "ZKTeco CCTV 카메라 취약점, 인증되지 않은 포트를 통해 자격 증명 노출"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "ko"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 ZKTeco CCTV 카메라의 CVE-2026-8598에 대해 경고합니다. 이 취약점은 문서화되지 않은 포트를 통해 자격 증명 탈취를 가능하게 합니다. 패치는 펌웨어 V5.0.1.2.20260421에서 제공됩니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "ZKTeco CCTV 카메라"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 ZKTeco CCTV 카메라의 CVE-2026-8598에 대해 경고합니다. 이 취약점은 문서화되지 않은 포트를 통해 자격 증명 탈취를 가능하게 합니다. 패치는 펌웨어 V5.0.1.2.20260421에서 제공됩니다.

{{< cyber-report severity="Critical" source="CISA" target="ZKTeco CCTV 카메라" cve="CVE-2026-8598" cvss="9.1" >}}

CISA가 ZKTeco CCTV 카메라의 심각한 인증 우회 취약점에 대한 권고(ICSA-26-139-04)를 발표했습니다. CVE-2026-8598로 추적되는 이 결함은 인증 없이 접근 가능한 문서화되지 않은 구성 내보내기 포트와 관련됩니다. 성공적으로 악용될 경우 카메라 계정 자격 증명 탈취를 포함한 정보 노출로 이어질 수 있습니다.

{{< ad-banner >}}

이 취약점은 V5.0.1.2.20260421 이전의 ZKTeco SSC335-GC2063-Face-0b77 솔루션 펌웨어 버전에 영향을 미칩니다. CVSS v3 기본 점수는 9.1로 심각도가 치명적입니다. 영향을 받는 장치는 전 세계 상업 시설에 배포되어 있으며, 공급업체는 중국에 본사를 두고 있습니다.

ZKTeco는 이 문제를 해결하기 위해 패치된 펌웨어 버전 V5.0.1.2.20260421을 출시했습니다. 사용자는 즉시 업그레이드할 것을 강력히 권장합니다. 이 취약점은 CWE-288(대체 경로 또는 채널을 사용한 인증 우회)로 분류됩니다.

{{< netrunner-insight >}}

이는 노출된 디버그 인터페이스가 백도어가 되는 전형적인 사례입니다. SOC 분석가는 즉시 네트워크에서 ZKTeco 카메라를 스캔하고 펌웨어 버전을 확인해야 합니다. DevSecOps의 경우, 이는 IoT 펌웨어 빌드에서 문서화되지 않은 포트를 비활성화하거나 방화벽으로 차단해야 함을 강조합니다. V5.0.1.2.20260421 미만의 펌웨어를 사용하는 모든 카메라는 반대로 입증될 때까지 손상된 것으로 간주하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
