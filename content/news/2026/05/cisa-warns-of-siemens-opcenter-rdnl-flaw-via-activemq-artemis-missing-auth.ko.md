---
title: "CISA, ActiveMQ Artemis 인증 누락을 통한 Siemens Opcenter RDnL 결함 경고"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnL이 CVE-2026-27446의 영향을 받습니다. 이는 ActiveMQ Artemis의 인증 누락 취약점으로, 인증되지 않은 인접 공격자가 메시지를 주입하거나 유출할 수 있습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnL이 CVE-2026-27446의 영향을 받습니다. 이는 ActiveMQ Artemis의 인증 누락 취약점으로, 인증되지 않은 인접 공격자가 메시지를 주입하거나 유출할 수 있습니다.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISA는 Apache ActiveMQ Artemis의 중요한 기능에 대한 인증 누락 취약점을 설명하는 권고(ICSA-26-134-09)를 발표했으며, 이는 Siemens Opcenter RDnL에 영향을 미칩니다. CVE-2026-27446으로 추적되고 CVSS v3 점수 7.1인 이 결함은 인접 네트워크 내의 인증되지 않은 공격자가 대상 브로커가 악성 브로커에 대한 아웃바운드 Core 페더레이션 연결을 설정하도록 강제할 수 있습니다. 이로 인해 악성 브로커를 통해 모든 큐에 메시지가 주입되거나 모든 큐에서 메시지가 유출될 수 있습니다.

{{< ad-banner >}}

이 취약점은 Siemens Opcenter RDnL의 모든 버전에 영향을 미칩니다. 자동 새로 고침 기능이 없고 메시지에 기밀 정보가 포함되지 않아 무결성 영향은 낮은 것으로 간주되지만, 가용성 영향과 메시지 조작 가능성은 여전히 중요합니다. ActiveMQ Artemis는 수정 사항을 출시했으며, Siemens는 즉시 최신 버전으로 업데이트할 것을 권장합니다.

전 세계적으로 중요한 제조 부문에 배포된 점을 고려하여, Opcenter RDnL을 사용하는 조직은 패치 적용을 우선시해야 합니다. 인접 네트워크 공격 벡터는 즉각적인 노출을 줄이지만, 분할된 환경에서도 여전히 위험을 제기합니다. 블루 팀은 비정상적인 Core 페더레이션 연결과 악성 브로커 활동을 모니터링해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, ActiveMQ Artemis 브로커에서 예상치 못한 아웃바운드 Core 페더레이션 연결을 모니터링하세요. 이것이 악용의 주요 지표입니다. DevSecOps 팀은 즉시 최신 ActiveMQ Artemis 버전으로 업데이트하고 Core 프로토콜 액세스를 신뢰할 수 있는 네트워크로만 제한해야 합니다. 이 결함은 즉각적인 영향이 낮아 보이더라도 미들웨어 구성 요소에서 인증 누락의 위험을 강조합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
