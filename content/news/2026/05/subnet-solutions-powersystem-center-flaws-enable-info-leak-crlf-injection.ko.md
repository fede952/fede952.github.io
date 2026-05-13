---
title: "Subnet Solutions PowerSYSTEM Center 결함으로 정보 유출 및 CRLF 인젝션 가능"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "ko"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA는 Subnet Solutions PowerSYSTEM Center의 여러 취약점에 대해 경고하며, 정보 노출 및 CRLF 인젝션을 포함한 이 취약점이 2020년부터 2026년까지의 버전에 영향을 미친다고 밝혔습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA는 Subnet Solutions PowerSYSTEM Center의 여러 취약점에 대해 경고하며, 정보 노출 및 CRLF 인젝션을 포함한 이 취약점이 2020년부터 2026년까지의 버전에 영향을 미친다고 밝혔습니다.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA는 중요 제조 및 에너지 분야에서 사용되는 플랫폼인 Subnet Solutions PowerSYSTEM Center의 여러 취약점을 상세히 설명하는 권고(ICSA-26-132-02)를 발표했습니다. 이 결함에는 제한된 권한을 가진 인증된 사용자가 장치 계정을 내보내고 일반적으로 관리자에게만 제한된 민감한 정보를 노출할 수 있는 잘못된 권한 부여(CVE-2026-26289)가 포함됩니다. 또한 CRLF 인젝션 취약점(CVE-2026-35504, CVE-2026-33570, CVE-2026-35555)으로 인해 공격자가 악의적인 헤더나 응답을 주입할 수 있습니다.

{{< ad-banner >}}

영향을 받는 버전은 PowerSYSTEM Center 2020(5.8.x ~ 5.28.x), 2024(6.0.x ~ 6.1.x), 2026(7.0.x)입니다. 이 취약점들은 CVSS v3 기본 점수 8.2로 높은 심각도를 나타냅니다. 성공적인 악용 시 정보 노출 및 잠재적인 세션 조작이나 HTTP 응답 분할로 이어질 수 있습니다.

이 제품이 전 세계 중요 인프라에 배포되어 있음을 고려할 때, 조직은 패치 적용을 우선시해야 합니다. Subnet Solutions는 업데이트를 출시했을 가능성이 높으며, 관리자는 공급업체의 보안 권고를 참조하고 최신 패치를 적용하는 것이 좋습니다. 그때까지 PowerSYSTEM Center에 대한 네트워크 액세스를 제한하고 비정상적인 활동을 모니터링하십시오.

{{< netrunner-insight >}}

SOC 분석가의 경우, 비정상적인 장치 계정 내보내기에 대한 인증 로그를 모니터링하십시오. 이는 CVE-2026-26289 악용의 명백한 징후입니다. DevSecOps 팀은 즉시 PowerSYSTEM Center 버전을 인벤토리화하고 패치를 적용해야 합니다. CRLF 인젝션 벡터(CVE-2026-35504 등)는 다른 공격과 연계되어 세션 무결성을 손상시킬 수 있기 때문입니다. CVSS 8.2 점수와 중요 분야 노출을 고려하여 높은 우선순위로 수정하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
