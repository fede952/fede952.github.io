---
title: "CISA, ABB AWIN 게이트웨이 재부팅 및 데이터 유출 허용하는 취약점 경고"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB AWIN 게이트웨이에 공격자가 장치를 재부팅하거나 시스템 구성을 추출할 수 있는 취약점이 있습니다. CISA 권고 ICSA-26-120-05는 CVE-2025-13777 및 수정 사항을 설명합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "ABB AWIN 게이트웨이"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB AWIN 게이트웨이에 공격자가 장치를 재부팅하거나 시스템 구성을 추출할 수 있는 취약점이 있습니다. CISA 권고 ICSA-26-120-05는 CVE-2025-13777 및 수정 사항을 설명합니다.

{{< cyber-report severity="High" source="CISA" target="ABB AWIN 게이트웨이" cve="CVE-2025-13777" cvss="8.3" >}}

CISA는 ABB AWIN 게이트웨이의 여러 취약점을 상세히 설명하는 권고 ICSA-26-120-05를 발표했습니다. 캡처-재전송을 통한 인증 우회 및 중요 기능에 대한 인증 부재를 포함한 이 결함으로 인해 인증되지 않은 공격자가 원격으로 장치를 재부팅하거나 민감한 시스템 구성 데이터를 조회할 수 있습니다. 이 취약점은 GW100 rev.2 및 GW120 하드웨어에서 실행되는 AWIN 펌웨어 버전 2.0-0, 2.0-1, 1.2-0 및 1.2-1에 영향을 미칩니다.

{{< ad-banner >}}

CVE-2025-13777로 추적되는 가장 심각한 문제는 인증되지 않은 쿼리를 통해 민감한 세부 정보를 포함한 시스템 구성을 노출할 수 있게 합니다. 권고는 CVSS v3 기본 점수 8.3을 할당하여 높은 심각도를 나타냅니다. ABB는 이러한 취약점을 해결하기 위해 GW100 rev.2용 펌웨어 버전 2.1-0을 출시했습니다. 영향을 받는 게이트웨이를 사용하는 조직은 즉시 업데이트를 적용하는 것이 좋습니다.

이 취약점은 전 세계에 배포된 중요 제조 부문 자산에 영향을 미칩니다. 인증 없이 원격 악용 가능성을 고려할 때, 이러한 결함은 운영 기술 환경에 상당한 위험을 초래합니다. CISA는 사용자가 전체 권고를 검토하고 네트워크 분할 및 영향을 받는 장치에 대한 액세스 제한을 포함한 완화 조치를 구현할 것을 권장합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우: ABB 게이트웨이에 대한 무단 재부팅 또는 비정상적인 쿼리를 모니터링하십시오. 이는 악용의 저소음 지표입니다. DevSecOps 팀은 펌웨어 2.1-0으로 패치를 우선 적용하고 엄격한 네트워크 액세스 제어를 시행해야 합니다. 취약점은 인증이 필요 없으며 원격으로 악용될 수 있기 때문입니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
