---
title: "Hitachi Energy ITT600 Explorer, libexpat 결함으로 DoS 취약"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "ko"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA는 Hitachi Energy ITT600 Explorer에서 서비스 거부 공격을 허용할 수 있는 두 가지 취약점을 경고합니다. 2.1 SP6 이전 버전에 영향을 미칩니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA는 Hitachi Energy ITT600 Explorer에서 서비스 거부 공격을 허용할 수 있는 두 가지 취약점을 경고합니다. 2.1 SP6 이전 버전에 영향을 미칩니다.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

Hitachi Energy는 ITT600 Explorer 제품에서 2.1 SP6 이전 버전에 영향을 미치는 취약점을 공개했습니다. CVE-2024-8176 및 CVE-2025-59375로 식별된 결함은 제어되지 않은 재귀와 제한 또는 조절 없이 리소스를 할당하는 문제를 포함합니다. 이러한 문제는 서비스 거부(DoS) 상태를 유발하기 위해 악용될 수 있습니다.

{{< ad-banner >}}

취약점은 IEC61850 기능에서 사용되는 libexpat 라이브러리에 존재합니다. 로컬 액세스 권한이 있는 공격자는 조작된 IEC61850 메시지를 보내 스택 오버플로를 유발하여 DoS 외에도 메모리 손상을 초래할 수 있습니다. 중요한 점은 ITT600 Explorer 제품만 영향을 받으며 IEC 61850 시스템 엔드포인트는 영향을 받지 않습니다.

CISA는 완화 조치나 업데이트를 즉시 적용할 것을 권장합니다. 이 제품은 에너지 부문 전 세계에 배포되어 있으며, 악용 시 중요 인프라 운영을 방해할 수 있습니다. 영향을 받는 버전을 사용하는 조직은 패치를 우선시하고 자세한 수정 단계는 권고를 검토해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우 악용 시도를 나타낼 수 있는 비정상적인 IEC61850 트래픽 패턴을 모니터링하십시오. DevSecOps 팀은 ITT600 Explorer를 버전 2.1 SP6 이상으로 업데이트하고 네트워크 분할을 고려하여 도구에 대한 로컬 액세스를 제한해야 합니다. CVSS 점수 7.5와 메모리 손상 가능성을 고려하여 높은 우선순위 패치로 처리하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
