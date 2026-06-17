---
title: "CISA, Rockwell Automation CompactLogix 컨트롤러의 DoS 취약점 경고"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Rockwell Automation CompactLogix 5370 컨트롤러의 여러 취약점으로 인해 서비스 거부 공격이 발생할 수 있습니다. CVE-2025-11694가 그 중 하나입니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Rockwell Automation CompactLogix 5370 컨트롤러"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Rockwell Automation CompactLogix 5370 컨트롤러의 여러 취약점으로 인해 서비스 거부 공격이 발생할 수 있습니다. CVE-2025-11694가 그 중 하나입니다.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation CompactLogix 5370 컨트롤러" cve="CVE-2025-11694" cvss="7.5" >}}

CISA는 Rockwell Automation CompactLogix 5370 컨트롤러(L1, L2, L3)의 취약점을 상세히 설명하는 권고(ICSA-26-167-04)를 발표했습니다. 이 결함에는 무결성 검사 값의 부적절한 검증과 민감한 시스템 정보 노출이 포함되어 있어, 공격자가 서비스 거부 상태를 유발할 수 있습니다. 이 권고는 V38.011 이전 버전에 영향을 미칩니다.

{{< ad-banner >}}

가장 주목할 만한 취약점인 CVE-2025-11694는 CIP 프로토콜에서 시퀀스 번호와 소스 IP 주소의 검증 누락과 관련이 있습니다. 공격자는 웹 인터페이스에 노출된 연결 ID를 악용하여 서비스 거부 공격을 수행할 수 있으며, 이로 인해 경미한 오류가 발생합니다. 이 취약점의 CVSS v3 점수는 7.5입니다.

Rockwell Automation은 이러한 문제를 해결하기 위해 V38.011로 업데이트할 것을 권장합니다. 영향을 받는 제품은 전 세계 Critical Manufacturing 부문에 배포되어 있습니다. 조직은 잠재적인 운영 중단을 완화하기 위해 이러한 컨트롤러에 패치를 적용하는 것을 우선시해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, CompactLogix 컨트롤러를 대상으로 하는 비정상적인 CIP 트래픽 패턴이나 반복적인 연결 시도를 모니터링하십시오. DevSecOps 엔지니어는 웹 인터페이스가 신뢰할 수 없는 네트워크에 노출되지 않도록 하고 펌웨어 업데이트를 V38.011로 신속히 적용해야 합니다. 이는 적절한 네트워크 분할과 패치 관리를 통해 완화할 수 있는 간단한 DoS 벡터입니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
