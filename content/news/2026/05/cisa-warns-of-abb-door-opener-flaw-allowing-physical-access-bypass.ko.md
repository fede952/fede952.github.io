---
title: "CISA, 물리적 접근 우회를 허용하는 ABB 도어 오프너 결함 경고"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 권고 ICSA-26-148-04는 ABB Busch-Welcome 2 Wire 도어 오프너 액추에이터의 인증 우회 취약점(CVE-2025-7705)을 설명하며, 이로 인해 건물에 대한 무단 접근이 가능해집니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "ABB Busch-Welcome 2 Wire 도어 오프너 액추에이터"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 권고 ICSA-26-148-04는 ABB Busch-Welcome 2 Wire 도어 오프너 액추에이터의 인증 우회 취약점(CVE-2025-7705)을 설명하며, 이로 인해 건물에 대한 무단 접근이 가능해집니다.

{{< cyber-report severity="Medium" source="CISA" target="ABB Busch-Welcome 2 Wire 도어 오프너 액추에이터" cve="CVE-2025-7705" cvss="6.8" >}}

CISA는 ABB Busch-Welcome 2 Wire 도어 오프너 액추에이터의 인증 우회 취약점(CVE-2025-7705)에 관한 권고 ICSA-26-148-04를 발표했습니다. 이 결함은 기본적으로 활성화된 호환 모드에서 비롯되며, 공격자가 해당 제품이 설치된 건물에 물리적으로 무단 접근할 수 있게 합니다. 이 취약점은 Switch Actuator 4 DU 및 Switch actuator, door/light 4 DU의 모든 버전에 영향을 미칩니다.

{{< ad-banner >}}

이 취약점의 CVSS v3 기본 점수는 6.8로 중간 심각도를 나타냅니다. ABB는 제품의 모드 스위치를 전환하고 전원을 재설정하여 시스템을 재보정하는 완화 조치를 제공했습니다. 이 제품은 전 세계, 주로 상업 시설에 배포되며, 공급업체는 스위스에 본사를 두고 있습니다.

영향을 받는 ABB Busch-Welcome 시스템을 사용하는 조직은 즉시 권장 완화 조치를 적용해야 합니다. 물리적 보안에 미치는 영향을 고려할 때, 이 취약점은 건물 출입 통제에 심각한 위험을 초래합니다. 보안 팀은 재보정 단계가 올바르게 실행되었는지 확인하고 악용 징후를 모니터링해야 합니다.

{{< netrunner-insight >}}

이 취약점은 IoT 및 건물 자동화 장치가 종종 안전하지 않은 기본 설정으로 출하된다는 사실을 극명하게 상기시킵니다. SOC 분석가는 ABB Busch-Welcome 시스템에 대한 자산 검색을 우선시하고 수동 재보정이 적용되었는지 확인해야 합니다. DevSecOps 팀은 특히 물리적 접근을 제어하는 장치에 대해 보안 중심 설계 원칙을 지지해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
