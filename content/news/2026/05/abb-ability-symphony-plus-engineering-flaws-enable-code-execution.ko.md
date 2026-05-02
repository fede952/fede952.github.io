---
title: "ABB Ability Symphony Plus Engineering 결함으로 코드 실행 가능"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "ko"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 오래된 PostgreSQL로 인한 ABB Ability Symphony Plus Engineering의 취약점을 경고하며, 영향을 받는 시스템에서 임의 코드 실행이 가능합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 오래된 PostgreSQL로 인한 ABB Ability Symphony Plus Engineering의 취약점을 경고하며, 영향을 받는 시스템에서 임의 코드 실행이 가능합니다.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA는 ABB Ability Symphony Plus Engineering의 여러 취약점을 상세히 설명하는 권고(ICSA-26-120-06)를 발표했습니다. 이 취약점은 PostgreSQL 버전 13.11 및 이전 버전 사용에서 비롯되며, 정수 오버플로, SQL 인젝션, TOCTOU 경쟁 조건, 권한 드롭 오류 등을 포함하여 인증된 공격자가 시스템에서 임의 코드를 실행할 수 있습니다.

{{< ad-banner >}}

영향을 받는 버전은 Ability Symphony Plus 2.2부터 2.4 SP2 RU1까지입니다. 이 취약점은 화학, 중요 제조, 에너지, 물 및 폐수 처리 등 전 세계 중요 인프라 부문에 걸쳐 제품이 배포되어 있어 특히 우려됩니다.

가장 주목할 만한 취약점인 CVE-2023-5869는 CVSS 점수 8.8을 가지며, 인증된 PostgreSQL 사용자가 조작된 데이터를 통해 트리거할 수 있는 정수 오버플로를 포함합니다. 성공적인 악용은 전체 시스템 손상으로 이어질 수 있어 즉각적인 패치의 필요성을 강조합니다.

{{< netrunner-insight >}}

이 권고는 OT 환경에서 오래된 종속성의 위험을 강조합니다. SOC 분석가는 ABB Symphony Plus 인스턴스에 대한 자산 검색을 우선시하고 PostgreSQL이 13.11 이상으로 업데이트되었는지 확인해야 합니다. DevSecOps 팀은 산업 제어 시스템을 위한 CI/CD 파이프라인에 종속성 스캐닝을 통합하여 이러한 상속된 취약점을 조기에 발견해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
