---
title: "CISA, ABB Camera Connect 결함에 대해 VLC 미디어 플레이어 구성 요소를 통해 경고"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect 버전 ≤1.5.0.14에는 취약한 VLC 미디어 플레이어 2.2.4가 포함되어 있으며, CVE-2024-46461을 포함한 여러 메모리 손상 버그가 있어 심각한 위험을 초래합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect 버전 ≤1.5.0.14에는 취약한 VLC 미디어 플레이어 2.2.4가 포함되어 있으며, CVE-2024-46461을 포함한 여러 메모리 손상 버그가 있어 심각한 위험을 초래합니다.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISA는 ABB Ability Camera Connect 버전 1.5.0.14 및 이하에서 여러 취약점을 상세히 설명하는 권고(ICSA-26-146-05)를 발표했습니다. 이러한 결함은 설치 패키지에 번들로 제공되는 오래된 타사 구성 요소인 VLC 미디어 플레이어 버전 2.2.4에서 비롯됩니다. 버전 1.5.0.15로 업데이트하면 취약한 구성 요소를 교체하여 문제가 해결됩니다.

{{< ad-banner >}}

취약점에는 힙 기반 버퍼 오버플로, 정수 언더플로, 범위를 벗어난 쓰기, 제어되지 않은 검색 경로 요소, 정수 오버플로, 오프바이원 오류, 범위를 벗어난 읽기, 이중 해제, 메모리 버퍼 내 작업의 부적절한 제한, 사용 후 해제 등이 포함됩니다. 특히 CVE-2024-46461은 악의적으로 조작된 MMS 스트림을 통해 VLC 미디어 플레이어 3.0.20 및 이전 버전에서 힙 기반 오버플로를 설명하여 서비스 거부를 유발합니다.

CVSS v3 점수 9.8로 이러한 취약점은 심각도가 Critical로 평가됩니다. 영향을 받는 중요 인프라 부문에는 화학, 상업 시설, 통신, 중요 제조, 에너지 및 운송 시스템이 포함됩니다. 이 제품은 전 세계에 배포되며, 악용될 경우 공격자가 다양한 방식으로 시스템을 손상시킬 수 있습니다.

{{< netrunner-insight >}}

이 권고는 타사 구성 요소에서 상속된 취약점의 위험을 강조합니다. SOC 분석가는 ABB Ability Camera Connect를 버전 1.5.0.15로 패치하고 VLC 미디어 플레이어 결함을 대상으로 하는 악용 시도를 모니터링해야 합니다. DevSecOps 팀은 엄격한 구성 요소 버전 관리와 번들 라이브러리의 정기적인 스캔을 시행해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
