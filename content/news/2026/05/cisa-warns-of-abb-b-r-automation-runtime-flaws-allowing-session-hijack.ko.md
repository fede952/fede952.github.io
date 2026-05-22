---
title: "CISA, ABB B&R Automation Runtime의 세션 하이재킹 취약점 경고"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB B&R Automation Runtime 6.4 이전 버전의 여러 취약점으로 인해 공격자가 세션을 하이재킹하거나 코드를 실행할 수 있습니다. CISA 권고 ICSA-26-141-04에 수정 사항이 설명되어 있습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB B&R Automation Runtime 6.4 이전 버전의 여러 취약점으로 인해 공격자가 세션을 하이재킹하거나 코드를 실행할 수 있습니다. CISA 권고 ICSA-26-141-04에 수정 사항이 설명되어 있습니다.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISA는 산업 자동화에 사용되는 소프트웨어 플랫폼인 ABB B&R Automation Runtime의 여러 취약점을 자세히 설명하는 권고 ICSA-26-141-04를 발표했습니다. B&R의 내부 보안 분석을 통해 확인된 이 결함은 6.4 이전 버전에 영향을 미치며 CVE-2025-3449(예측 가능한 세션 식별자), CVE-2025-3448(교차 사이트 스크립팅), CVE-2025-11498(CSV 파일의 수식 요소 부적절한 중화)을 포함합니다. 인증되지 않은 공격자가 이를 악용하여 원격 세션을 하이재킹하거나 사용자 브라우저 컨텍스트에서 코드를 실행할 수 있습니다.

{{< ad-banner >}}

가장 심각한 취약점인 CVE-2025-3449는 System Diagnostic Manager(SDM) 구성 요소에 있으며 CVSS v3 점수는 6.1입니다. 이 취약점은 예측 가능한 숫자 또는 식별자 생성으로 인해 인증되지 않은 네트워크 기반 공격자가 이미 설정된 세션을 탈취할 수 있게 합니다. SDM은 Automation Runtime 6에서 기본적으로 비활성화되어 있어 노출을 줄일 수 있지만, 조직은 명시적으로 필요하지 않은 경우 SDM이 꺼져 있는지 확인해야 합니다.

ABB는 이러한 문제를 해결하기 위해 Automation Runtime 버전 6.4를 출시했습니다. 이 제품이 전 세계 에너지 부문에 걸쳐 배포되어 있음을 고려하여 CISA는 운영자가 신속하게 업데이트를 적용할 것을 촉구합니다. 권고에 따르면 성공적인 악용은 원격 코드 실행 또는 세션 탈취로 이어질 수 있으며, 산업 제어 환경에 심각한 위험을 초래합니다.

{{< netrunner-insight >}}

SOC 분석가를 위한 조언: SDM이 활성화된 인스턴스를 우선적으로 패치하십시오. 예측 가능한 세션 ID 결함(CVE-2025-3449)은 네트워크를 통해 쉽게 악용될 수 있습니다. DevSecOps 팀은 프로덕션에서 SDM이 비활성화된 상태로 유지되고 노출된 인스턴스가 신뢰할 수 없는 네트워크에서 접근 가능하지 않은지 확인해야 합니다. 비정상적인 세션 활동을 탐지 신호로 모니터링하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
