---
title: "새로운 Java 기반 QuimaRAT MaaS, Windows, Linux, macOS 대상"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "ko"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "크로스 플랫폼 Java RAT인 QuimaRAT가 서비스형 악성코드로 판매되며 Windows, Linux, macOS 시스템을 위협합니다. LevelBlue의 연구원들이 구독 모델과 기능을 상세히 설명합니다."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "Windows, Linux, macOS 시스템"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

크로스 플랫폼 Java RAT인 QuimaRAT가 서비스형 악성코드로 판매되며 Windows, Linux, macOS 시스템을 위협합니다. LevelBlue의 연구원들이 구독 모델과 기능을 상세히 설명합니다.

{{< cyber-report severity="High" source="The Hacker News" target="Windows, Linux, macOS 시스템" >}}

LevelBlue의 사이버 보안 연구원들은 QuimaRAT이라는 새로운 Java 기반 원격 접근 트로이목마(RAT)를 식별했으며, 이는 Windows, Linux, macOS 환경을 대상으로 할 수 있습니다. 이 악성코드는 서비스형 악성코드(MaaS) 모델로 판매되며, 구독 등급은 1개월 150달러부터 평생 액세스 1,200달러, 그리고 300달러 등급이 있습니다.

{{< ad-banner >}}

Java로 구현된 QuimaRAT의 크로스 플랫폼 특성은 다양한 운영 체제를 손상시킬 수 있어 이기종 환경을 가진 조직에 다재다능한 위협이 됩니다. MaaS 모델은 숙련도가 낮은 위협 행위자의 진입 장벽을 낮추어 공격 빈도를 증가시킬 수 있습니다.

초기 보고서에서 QuimaRAT의 기능에 대한 구체적인 기술적 세부 사항은 제한적이지만, Java 기반 아키텍처는 키로깅, 화면 캡처, 파일 유출과 같은 일반적인 기술을 활용할 수 있음을 시사합니다. 조직은 의심스러운 Java 프로세스를 모니터링하고 애플리케이션 허용 목록을 구현하여 위험을 완화해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, QuimaRAT의 크로스 플랫폼 특성으로 인해 탐지 규칙이 Windows, Linux, macOS 엔드포인트를 모두 포함해야 합니다. DevSecOps 팀은 Java 런타임 사용을 검토하고 서명되지 않은 Java 애플리케이션의 실행을 제한하는 것을 고려해야 합니다. MaaS 모델을 고려할 때, 숙련도가 낮은 공격자가 이 RAT를 배포할 것으로 예상되므로 비정상적인 네트워크 연결 및 프로세스 동작에 대한 기준 모니터링이 중요합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
