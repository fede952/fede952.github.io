---
title: "Mandiant, Cisco SD-WAN 제로데이 루트 액세스 공격 적발"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "ko"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "새로운 세부 정보에 따르면 해커들이 CVE-2026-20245를 제로데이 공격에 악용하여 Cisco Catalyst SD-WAN 장치에 불법 루트 계정을 생성한 것으로 나타났습니다."
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "Cisco Catalyst SD-WAN 장치"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

새로운 세부 정보에 따르면 해커들이 CVE-2026-20245를 제로데이 공격에 악용하여 Cisco Catalyst SD-WAN 장치에 불법 루트 계정을 생성한 것으로 나타났습니다.

{{< cyber-report severity="High" source="BleepingComputer" target="Cisco Catalyst SD-WAN 장치" cve="CVE-2026-20245" >}}

Mandiant는 위협 행위자들이 Cisco Catalyst SD-WAN 소프트웨어의 제로데이 취약점(CVE-2026-20245)을 악용하여 대상 장치에 루트 액세스 권한을 획득한 방법에 대한 새로운 기술적 세부 정보를 공개했습니다. 이 공격은 불법 루트 계정을 생성하여 지속적인 무단 액세스를 가능하게 했습니다.

{{< ad-banner >}}

Cisco가 최신 권고에서 패치한 이 취약점은 제한적이고 표적화된 공격에 사용되었습니다. Mandiant의 분석은 특정 익스플로잇 체인을 밝혀내며 보안 업데이트를 신속하게 적용하는 것의 중요성을 강조합니다.

Cisco SD-WAN 솔루션을 사용하는 조직은 승인되지 않은 계정이나 비정상적인 루트 수준 활동과 같은 침해 징후가 있는지 시스템을 감사할 것을 권고합니다. 이 사건은 강력한 패치 관리와 네트워크 인프라 모니터링의 중요성을 강조합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우 Cisco SD-WAN 어플라이언스에서 승인되지 않은 계정 생성 및 권한 상승 이벤트를 모니터링하는 데 우선순위를 두십시오. DevSecOps 팀은 Cisco의 보안 패치를 신속하게 배포하고 SD-WAN 관리 인터페이스를 분리하여 공격 표면을 줄이는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
