---
title: "CISA, Naxclow IoT 플랫폼의 장치 탈취 가능한 치명적 결함 경고"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Naxclow IoT 플랫폼의 여러 취약점(CVE-2026-42947 포함)으로 인해 장치 하이재킹 및 자격 증명 수집이 가능합니다. 스마트 초인종과 홈 허브에 영향을 미칩니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Naxclow IoT 플랫폼 장치"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Naxclow IoT 플랫폼의 여러 취약점(CVE-2026-42947 포함)으로 인해 장치 하이재킹 및 자격 증명 수집이 가능합니다. 스마트 초인종과 홈 허브에 영향을 미칩니다.

{{< cyber-report severity="Critical" source="CISA" target="Naxclow IoT 플랫폼 장치" cve="CVE-2026-42947" cvss="9.8" >}}

CISA는 Naxclow IoT 플랫폼의 여러 취약점을 상세히 설명하는 권고(ICSA-26-162-02)를 발표했습니다. 이 취약점은 Smart Doorbell X3, X Smart Home, V720, ix cam과 같은 제품에 영향을 미칩니다. 가장 심각한 결함인 CVE-2026-42947은 CVSS 점수 9.8을 가지며, 사용자 제어 키를 통한 권한 부여 우회를 포함하여 공격자가 사용자 상호 작용 없이 confirm-then-bind 시퀀스를 재생하여 장치를 임의의 계정에 조용히 재할당할 수 있게 합니다.

{{< ad-banner >}}

추가적인 약점으로는 권한 부여 확인 누락, 하드코딩된 암호화 키 사용, 예측 가능한 식별자 생성, 외부에서 접근 가능한 파일에 민감한 정보 삽입 등이 있습니다. 성공적으로 악용될 경우 장치 사칭, 통신 가로채기 또는 조작, 대규모 자격 증명 수집, 영향을 받는 시스템에 대한 무단 액세스가 가능할 수 있습니다.

이 취약점은 나열된 제품의 모든 버전에 영향을 미치며, 장치는 전 세계 상업 시설에 배포되어 있습니다. 중국에 본사를 둔 Naxclow는 아직 패치를 출시하지 않았습니다. 이러한 장치를 사용하는 조직은 즉시 네트워크 분할 및 모니터링을 구현하여 비정상적인 장치 바인딩 활동을 탐지해야 합니다.

{{< netrunner-insight >}}

이것은 교과서적인 공급망 IoT 악몽입니다: 하드코딩된 키, 예측 가능한 ID, 재생 가능한 온보딩 흐름. SOC 팀은 로그에서 예상치 못한 장치 재할당을 찾아야 하며, 패치가 도착할 때까지 Naxclow 장치를 별도의 VLAN에 격리하는 것을 고려해야 합니다. DevSecOps는 IoT 온보딩에서 암호화 장치 ID와 상호 인증을 추진해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
