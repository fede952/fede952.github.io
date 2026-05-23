---
title: "ABB B&R Automation Studio 결함으로 ICS 원격 코드 실행 위험 노출"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "ko"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 ABB B&R Automation Studio의 25개 취약점에 대해 경고하며, CVSS 9.8의 심각한 버그가 무단 액세스 및 원격 코드 실행을 가능하게 할 수 있다고 밝혔습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 ABB B&R Automation Studio의 25개 취약점에 대해 경고하며, CVSS 9.8의 심각한 버그가 무단 액세스 및 원격 코드 실행을 가능하게 할 수 있다고 밝혔습니다.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISA는 ABB B&R Automation Studio의 여러 취약점에 대한 권고를 발표했으며, 이는 버전 6.5 이전 및 버전 6.5에 영향을 미칩니다. 권고에는 CVE-2025-6965, CVE-2025-3277, CVE-2023-7104 등 25개의 CVE가 포함되어 있습니다. 이러한 취약점은 오래된 타사 구성 요소에서 비롯되었으며, 힙 기반 버퍼 오버플로, 범위를 벗어난 쓰기, 사용 후 해제, 부적절한 입력 검증 등의 문제를 포함합니다.

{{< ad-banner >}}

ABB는 테스트 중 악용 사례가 관찰되지 않았다고 보고했지만, 이러한 취약점은 무단 액세스, 데이터 노출 또는 원격 코드 실행을 위한 공격 벡터를 제공할 수 있습니다. 가장 심각한 CVE는 CVSS v3 점수 9.8로, 심각한 위험도를 나타냅니다. 영향을 받는 제품은 산업 자동화 및 제어 시스템에 사용되므로 위협 행위자에게 매력적인 대상이 됩니다.

ABB는 오래된 타사 구성 요소를 대체하는 업데이트를 출시했습니다. B&R Automation Studio를 사용하는 조직은 즉시 업데이트를 적용하는 것이 좋습니다. 이러한 취약점의 심각성과 원격 악용 가능성을 고려하여, 자산 소유자는 패치 적용을 최우선으로 하고 손상 징후를 모니터링해야 합니다.

{{< netrunner-insight >}}

SOC 분석가와 DevSecOps 엔지니어에게 이 권고는 ICS 소프트웨어에서 타사 종속성의 위험을 강조합니다. 25개의 CVE라는 숫자는 구성 요소 관리의 체계적인 문제를 시사합니다. B&R Automation Studio 인스턴스의 인벤토리를 우선시하고 공급업체 업데이트를 적용하십시오. 또한 ICS 네트워크를 세분화하여 노출을 제한하고 악용 시도를 나타낼 수 있는 비정상적인 동작을 모니터링하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
