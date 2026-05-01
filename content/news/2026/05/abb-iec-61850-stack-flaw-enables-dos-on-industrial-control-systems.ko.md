---
title: "ABB IEC 61850 스택 결함, 산업 제어 시스템에 DoS 유발"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "ko"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA는 ABB의 IEC 61850 MMS 구현에서 비공개로 보고된 취약점이 System 800xA 및 Symphony Plus 제품에 영향을 미쳐 장치 결함 및 서비스 거부를 초래한다고 경고합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA는 ABB의 IEC 61850 MMS 구현에서 비공개로 보고된 취약점이 System 800xA 및 Symphony Plus 제품에 영향을 미쳐 장치 결함 및 서비스 거부를 초래한다고 경고합니다.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA는 MMS 클라이언트 애플리케이션을 위한 IEC 61850 통신 스택의 ABB 구현에서 취약점에 관한 권고(ICSA-26-120-01)를 발표했습니다. 이 결함은 AC800M CI868, Symphony Plus SD Series CI850, PM 877, S+ Operations를 포함한 System 800xA 및 Symphony Plus 라인의 여러 제품에 영향을 미칩니다. 악용하려면 사이트의 IEC 61850 네트워크에 대한 사전 접근이 필요합니다.

{{< ad-banner >}}

성공적인 악용은 PM 877, CI850 및 CI868 모듈에 장치 결함을 발생시켜 수동 재시작이 필요합니다. S+ Operations 노드의 경우 공격이 IEC 61850 통신 드라이버를 충돌시켜 반복되면 서비스 거부 상태를 초래합니다. 그러나 전체 노드 가용성과 기능은 영향을 받지 않으며 GOOSE 프로토콜 통신은 영향을 받지 않습니다. System 800xA IEC61850 Connect도 취약하지 않습니다.

영향을 받는 펌웨어 버전은 S+ Operations 최대 6.2.0006.0 및 다양한 PM 877 릴리스를 포함한 여러 브랜치에 걸쳐 있습니다. 권고에는 CVE 식별자나 CVSS 점수가 제공되지 않았습니다. 이러한 제품을 사용하는 조직은 권고를 검토하고 네트워크 분할 및 접근 제어와 같은 완화 조치를 적용하여 IEC 61850 네트워크에 대한 노출을 제한해야 합니다.

{{< netrunner-insight >}}

이 취약점은 OT 환경에서 네트워크 분할의 중요성을 강조합니다. 악용하려면 IEC 61850 네트워크에 대한 접근이 필요하므로 해당 네트워크를 기업 IT 및 인터넷과 분리하는 것이 중요합니다. SOC 분석가는 비정상적인 IEC 61850 트래픽을 모니터링해야 하며, DevSecOps 엔지니어는 패치 적용을 우선시하고 MMS 프로토콜 이상 징후 탐지를 위한 침입 탐지 구현을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
