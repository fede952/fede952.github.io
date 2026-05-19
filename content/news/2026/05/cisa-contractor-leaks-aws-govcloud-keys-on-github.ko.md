---
title: "CISA 계약업체, GitHub에 AWS GovCloud 키 유출"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "ko"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 계약업체가 공개 GitHub 저장소에 AWS GovCloud 자격 증명과 내부 빌드 세부 정보를 노출시켜, 가장 심각한 정부 데이터 유출 중 하나로 기록되었습니다."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "CISA AWS GovCloud 계정"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 계약업체가 공개 GitHub 저장소에 AWS GovCloud 자격 증명과 내부 빌드 세부 정보를 노출시켜, 가장 심각한 정부 데이터 유출 중 하나로 기록되었습니다.

{{< cyber-report severity="Critical" source="Krebs on Security" target="CISA AWS GovCloud 계정" >}}

이번 주말까지, 사이버보안 및 인프라 보안국(CISA)의 계약업체가 여러 높은 권한의 AWS GovCloud 계정과 다수의 내부 CISA 시스템에 대한 자격 증명을 노출한 공개 GitHub 저장소를 유지하고 있었습니다. 보안 전문가들은 이 공개 아카이브에 CISA가 내부적으로 소프트웨어를 구축, 테스트 및 배포하는 방법을 상세히 설명하는 파일이 포함되어 있으며, 이는 최근 역사상 가장 심각한 정부 데이터 유출 중 하나라고 말했습니다.

{{< ad-banner >}}

노출된 자격 증명은 공격자가 민감한 정부 클라우드 환경과 내부 시스템에 접근할 수 있게 하여, 데이터 유출이나 추가 침해로 이어질 수 있습니다. 이 사건은 정부 계약업체조차 공개 저장소에 하드코딩된 비밀의 위험성을 강조합니다.

{{< netrunner-insight >}}

이번 유출은 자동화된 비밀 스캐닝과 엄격한 저장소 접근 통제의 중요성을 강조합니다. SOC 분석가는 공개 코드 저장소에서 노출된 자격 증명을 모니터링하는 데 우선순위를 두어야 하며, DevSecOps 팀은 비밀 관리 정책을 시행하고 잠재적으로 손상된 키를 즉시 교체해야 합니다.

{{< /netrunner-insight >}}

---

**[Krebs on Security에서 전체 기사 읽기 ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
