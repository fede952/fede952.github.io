---
title: "Siemens Ruggedcom ROX 결함으로 인수 주입을 통해 루트 파일 읽기 가능"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "ko"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 여러 Ruggedcom ROX 장치에 영향을 미치는 CVE-2025-40948에 대해 경고합니다. 인증된 원격 공격자가 루트 권한으로 임의의 파일을 읽을 수 있습니다. v2.17.1 이상으로 업데이트하십시오."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Siemens Ruggedcom ROX 장치"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 여러 Ruggedcom ROX 장치에 영향을 미치는 CVE-2025-40948에 대해 경고합니다. 인증된 원격 공격자가 루트 권한으로 임의의 파일을 읽을 수 있습니다. v2.17.1 이상으로 업데이트하십시오.

{{< cyber-report severity="Medium" source="CISA" target="Siemens Ruggedcom ROX 장치" cve="CVE-2025-40948" cvss="6.8" >}}

Siemens Ruggedcom ROX 시리즈 장치는 인증된 원격 공격자가 기본 운영 체제에서 루트 권한으로 임의의 파일을 읽을 수 있는 부적절한 액세스 제어 취약점(CVE-2025-40948)의 영향을 받습니다. 이 결함은 웹 서버의 JSON-RPC 인터페이스에서 입력을 제대로 검증하지 않아 인수 주입이 가능하기 때문에 발생합니다.

{{< ad-banner >}}

다음 제품이 취약합니다: RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536 및 RX5000, 모두 2.17.1 이전 버전을 실행 중입니다. Siemens는 이 문제를 해결하기 위한 업데이트를 출시했으며 즉시 패치를 적용할 것을 권장합니다.

CVSS v3 점수 6.8로 이 취약점은 중간 심각도로 평가됩니다. 공격 벡터는 네트워크 기반이며 낮은 권한이 필요하고 사용자 상호 작용이 필요하지 않습니다. 이러한 장치가 배포된 중요 인프라 부문(예: 중요 제조)을 고려할 때 악용될 경우 심각한 정보 공개로 이어질 수 있습니다.

{{< netrunner-insight >}}

SOC 분석가를 위한 조언: 환경 내 Ruggedcom ROX 장치, 특히 신뢰할 수 없는 네트워크에 노출된 장치의 패치를 우선시하십시오. 익스플로잇의 인증된 특성은 즉각적인 위험을 줄이지만 완전히 제거하지는 않습니다. 낮은 권한 계정을 손상시킨 공격자는 전체 루트 파일 액세스로 권한을 상승시킬 수 있습니다. DevSecOps 팀은 JSON-RPC 엔드포인트 강화를 검토하고 네트워크 분할을 통해 노출을 제한해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
