---
title: "SAP npm 패키지, 자격 증명 탈취 공급망 공격에 피격"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "ko"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "'Mini Shai-Hulud'로 명명된 캠페인이 SAP 관련 npm 패키지를 대상으로 자격 증명 탈취 악성코드를 유포하며 여러 패키지에 영향을 미치고 있습니다. 여러 업체의 연구원들이 공급망 위험에 대해 경고하고 있습니다."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "SAP 관련 npm 패키지"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

'Mini Shai-Hulud'로 명명된 캠페인이 SAP 관련 npm 패키지를 대상으로 자격 증명 탈취 악성코드를 유포하며 여러 패키지에 영향을 미치고 있습니다. 여러 업체의 연구원들이 공급망 위험에 대해 경고하고 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="SAP 관련 npm 패키지" >}}

사이버보안 연구원들이 SAP 관련 npm 패키지를 표적으로 삼은 공급망 공격 캠페인을 발견했습니다. 'Mini Shai-Hulud'로 명명된 이 캠페인은 손상된 패키지를 통해 자격 증명 탈취 악성코드를 배포한다고 Aikido Security, Onapsis, OX Security, SafeDep, Socket, StepSecurity, Wiz의 보고서가 밝혔습니다.

{{< ad-banner >}}

이 공격은 SAP와 관련된 여러 npm 패키지에 영향을 미치지만, 구체적인 패키지 이름과 버전은 공개되지 않았습니다. 악성코드는 자격 증명을 탈취하도록 설계되어 공격자에게 민감한 SAP 환경 및 하위 시스템에 대한 접근 권한을 제공할 수 있습니다.

이번 사건은 특히 SAP와 같은 기업 핵심 플랫폼의 소프트웨어 공급망에 대한 증가하는 위협을 강조합니다. 영향을 받은 패키지를 사용하는 조직은 종속성을 감사하고 잠재적으로 손상된 자격 증명을 교체하는 것이 좋습니다.

{{< netrunner-insight >}}

SOC 분석가와 DevSecOps 팀에게 이번 공격은 npm 패키지에 대한 엄격한 종속성 스캔과 무결성 검사의 필요성을 강조합니다. SAP 관련 시스템에서 비정상적인 아웃바운드 연결을 모니터링하고 런타임 애플리케이션 자체 보호(RASP)를 구현하여 자격 증명 탈취를 탐지하는 것을 고려하십시오. 손상된 패키지를 통해 노출되었을 수 있는 모든 자격 증명을 즉시 교체하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
