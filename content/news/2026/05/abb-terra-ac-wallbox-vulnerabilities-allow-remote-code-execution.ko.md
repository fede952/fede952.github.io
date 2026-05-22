---
title: "ABB Terra AC Wallbox 취약점으로 원격 코드 실행 가능"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "ko"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA는 ABB Terra AC Wallbox (JP) ≤1.8.33에서 힙 및 스택 버퍼 오버플로를 경고합니다. CVE-2025-10504, CVE-2025-12142, CVE-2025-12143을 완화하려면 1.8.36으로 업데이트하십시오."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA는 ABB Terra AC Wallbox (JP) ≤1.8.33에서 힙 및 스택 버퍼 오버플로를 경고합니다. CVE-2025-10504, CVE-2025-12142, CVE-2025-12143을 완화하려면 1.8.36으로 업데이트하십시오.

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABB는 Terra AC Wallbox (JP) 제품 라인, 특히 버전 1.8.33 이하에 영향을 미치는 여러 취약점을 공개했습니다. 결함에는 힙 기반 버퍼 오버플로(CVE-2025-10504), 입력 크기를 확인하지 않은 버퍼 복사(CVE-2025-12142), 스택 기반 버퍼 오버플로(CVE-2025-12143)가 포함됩니다. 성공적으로 악용될 경우 공격자가 힙 메모리를 손상시켜 장치를 원격으로 제어하고 플래시 메모리에 무단 쓰기를 수행하여 펌웨어 동작을 변경할 수 있습니다.

{{< ad-banner >}}

이 취약점들은 CVSS v3 기본 점수 6.1로 평가되어 중간 심각도를 나타냅니다. ABB는 이러한 문제를 해결하기 위해 펌웨어 버전 1.8.36을 출시했습니다. 해당 제품은 에너지 분야에서 전 세계적으로 배포되며, 공급업체는 가능한 한 빨리 업데이트를 적용할 것을 권장합니다.

아직 활발한 악용 사례는 보고되지 않았지만, 원격 코드 실행 및 펌웨어 조작 가능성으로 인해 EV 충전 인프라 운영자에게 이 취약점들은 중요합니다. 조직은 신뢰할 수 없는 네트워크에 노출된 장치, 특히 영향을 받는 장치의 패치 적용을 우선시해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우 Terra AC Wallbox 장치로의 비정상 트래픽, 특히 플래시 메모리에 대한 예상치 못한 쓰기 작업을 모니터링하십시오. DevSecOps 엔지니어는 충전기와 통신하는 모든 사용자 정의 프로토콜에서 엄격한 입력 검증을 시행하고 펌웨어 업데이트를 신속히 적용해야 합니다. CVSS 점수 6.1을 고려하여 중간 우선순위로 처리하되, 중요한 에너지 인프라에서 장치의 역할로 인해 잠재적 영향이 크므로 주의하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
