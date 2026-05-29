---
title: "XCharge C6 EV 충전기의 심각한 결함으로 원격 코드 실행 가능"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "ko"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA는 XCharge C6 EV 충전 컨트롤러의 인증되지 않은 취약점(CVE-2026-9037, CVSS 점수 9.8)에 대해 경고합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "XCharge C6 EV 충전 컨트롤러"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA는 XCharge C6 EV 충전 컨트롤러의 인증되지 않은 취약점(CVE-2026-9037, CVSS 점수 9.8)에 대해 경고합니다.

{{< cyber-report severity="Critical" source="CISA" target="XCharge C6 EV 충전 컨트롤러" cve="CVE-2026-9037" cvss="9.8" >}}

CISA는 XCharge C6 전기차 충전 컨트롤러의 여러 심각한 취약점을 상세히 설명하는 권고(ICSA-26-148-08)를 발표했습니다. 결함에는 무결성 검사 없는 코드 다운로드(CWE-494), 스택 기반 버퍼 오버플로, 안전하지 않은 기본값으로 리소스 초기화가 포함됩니다. 성공적으로 악용될 경우 공격자가 장치에서 관리자 권한을 얻거나 임의 코드를 실행할 수 있습니다.

{{< ad-banner >}}

가장 심각한 취약점인 CVE-2026-9037은 펌웨어 패키지의 진위 여부를 검증하지 못하는 펌웨어 업데이트 메커니즘과 관련됩니다. 암호화 서명 확인이 없으면 관리 채널을 방해하거나 가장할 수 있는 공격자가 승인되지 않은 펌웨어를 설치하여 높은 권한의 코드 실행으로 이어질 수 있습니다. 이 취약점의 CVSS v3 점수는 9.8로 심각도를 나타냅니다.

XCharge는 2026년 5월 22일 기준으로 모든 영향을 받는 충전기에 대한 펌웨어 업데이트를 배포했습니다. 사용자는 장치가 업데이트되었는지 확인하고 필요한 경우 XCharge 지원팀에 문의하는 것이 좋습니다. 영향을 받는 제품은 여러 국가의 교통 시스템 부문에 널리 배포되어 있습니다.

{{< netrunner-insight >}}

SOC 분석가의 경우 XCharge C6 충전기의 관리 인터페이스에서 무단 액세스 또는 비정상적인 펌웨어 업데이트 요청을 모니터링하는 데 우선순위를 두십시오. DevSecOps 팀은 네트워크 분할을 적용하고 공급업체 패치를 즉시 적용해야 합니다. 무결성 검사 부족으로 인해 이러한 장치는 공급망 공격의 주요 대상이 됩니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
