---
title: "Siemens Solid Edge PAR 구문 분석 결함으로 코드 실행 가능"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "ko"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Solid Edge SE2026의 두 가지 파일 구문 분석 취약점으로 인해 공격자가 특수 제작된 PAR 파일을 통해 임의 코드를 실행할 수 있습니다. V226.0 Update 5로 업데이트하십시오."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Solid Edge SE2026의 두 가지 파일 구문 분석 취약점으로 인해 공격자가 특수 제작된 PAR 파일을 통해 임의 코드를 실행할 수 있습니다. V226.0 Update 5로 업데이트하십시오.

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

Siemens Solid Edge SE2026 Update 5 이전 버전은 애플리케이션이 특수 제작된 PAR 파일을 읽을 때 트리거될 수 있는 두 가지 파일 구문 분석 취약점의 영향을 받습니다. 결함에는 초기화되지 않은 포인터 액세스(CVE-2026-44411)와 스택 기반 버퍼 오버플로(CVE-2026-44412)가 포함되며, 두 가지 모두 공격자가 애플리케이션을 충돌시키거나 현재 프로세스의 컨텍스트에서 임의 코드를 실행할 수 있도록 허용할 수 있습니다.

{{< ad-banner >}}

이 취약점들은 CVSS v3.1 기본 점수 7.8(High)을 가지며, 벡터는 AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H로, 로컬 액세스, 낮은 복잡성, 권한 불필요, 사용자 상호 작용 필요, 기밀성, 무결성 및 가용성에 대한 높은 영향을 나타냅니다. Siemens는 이러한 문제를 해결하기 위해 V226.0 Update 5를 출시했으며, 사용자에게 즉시 업데이트할 것을 권장합니다.

전 세계적으로 중요한 제조 부문에 배포된 점을 고려하여 Solid Edge를 사용하는 조직은 패치 적용을 우선시해야 합니다. 이 취약점들은 사용자 상호 작용(악성 PAR 파일 열기)이 필요하므로, 사용자 인식 교육도 보완 통제로 권장됩니다.

{{< netrunner-insight >}}

SOC 분석가의 경우 Solid Edge 프로세스에서 비정상적인 PAR 파일 처리 또는 충돌을 모니터링하십시오. DevSecOps 엔지니어는 애플리케이션 허용 목록을 적용하고 파일 유형을 제한하여 공격 표면을 줄여야 합니다. 이는 로컬, 사용자 상호 작용 의존 취약점이므로 피싱 시뮬레이션과 의심스러운 파일 열기에 대한 엔드포인트 탐지 규칙이 주요 완화 조치입니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
