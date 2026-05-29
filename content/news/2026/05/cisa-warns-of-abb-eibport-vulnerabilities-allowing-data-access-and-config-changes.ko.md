---
title: "CISA, ABB EIBPORT 취약점 경고: 데이터 접근 및 구성 변경 가능"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB EIBPORT 장치에서 교차 사이트 스크립팅 및 세션 ID 도난 취약점이 발견되었습니다. 펌웨어 버전 3.9.2로 업데이트할 수 있습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "ABB EIBPORT 장치"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB EIBPORT 장치에서 교차 사이트 스크립팅 및 세션 ID 도난 취약점이 발견되었습니다. 펌웨어 버전 3.9.2로 업데이트할 수 있습니다.

{{< cyber-report severity="High" source="CISA" target="ABB EIBPORT 장치" cve="CVE-2021-22291" >}}

CISA는 ABB EIBPORT 장치, 특히 EIBPORT V3 KNX 및 EIBPORT V3 KNX GSM 모델의 여러 취약점에 대한 권고(ICSA-26-148-03)를 발표했습니다. 이 취약점에는 교차 사이트 스크립팅(XSS) 결함(CWE-79)과 세션 ID 도난 문제(CVE-2021-22291)가 포함되어 있으며, 공격자가 장치에 저장된 민감한 정보에 접근하고 구성을 변경할 수 있습니다.

{{< ad-banner >}}

영향을 받는 펌웨어 버전은 3.9.2 이전입니다. ABB는 비공개로 보고된 이러한 취약점을 해결하기 위해 펌웨어 업데이트를 출시했습니다. 이 제품은 전 세계적으로 주요 제조 및 정보 기술 분야에 배포되며, 공급업체는 스위스에 본사를 두고 있습니다.

권고에는 CVSS 점수가 제공되지 않았지만, 장치 무결성 및 기밀성에 대한 잠재적 영향으로 인해 신속한 패치 적용이 필요합니다. 영향을 받는 ABB EIBPORT 장치를 사용하는 조직은 악용 위험을 완화하기 위해 가능한 한 빨리 펌웨어 업데이트를 적용해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, 펌웨어 3.9.2 미만의 ABB EIBPORT 장치를 스캔하고 비정상적인 구성 변경이나 세션 이상을 모니터링하는 데 우선순위를 두십시오. DevSecOps 팀은 특히 건물 자동화 및 중요 인프라에서 장치의 역할을 고려하여 이 펌웨어 업데이트를 패치 관리 파이프라인에 통합해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
