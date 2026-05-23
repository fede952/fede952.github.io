---
title: "CISA 계약업체, AWS GovCloud 키를 공개 GitHub에 유출"
date: "2026-05-23T09:02:01Z"
original_date: "2026-05-22T16:34:24"
lang: "ko"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-public-github"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 계약업체가 의도적으로 AWS GovCloud 키와 기관 기밀을 공개 GitHub 계정에 게시한 후, CISA가 침해 사고를 통제하는 데 어려움을 겪으면서 의원들이 답변을 요구하고 있습니다."
original_url: "https://krebsonsecurity.com/2026/05/lawmakers-demand-answers-as-cisa-tries-to-contain-data-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA AWS GovCloud 환경"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 계약업체가 의도적으로 AWS GovCloud 키와 기관 기밀을 공개 GitHub 계정에 게시한 후, CISA가 침해 사고를 통제하는 데 어려움을 겪으면서 의원들이 답변을 요구하고 있습니다.

{{< cyber-report severity="High" source="Krebs on Security" target="CISA AWS GovCloud 환경" >}}

KrebsOnSecurity가 CISA 계약업체가 의도적으로 AWS GovCloud 키와 방대한 양의 기타 기관 기밀을 공개 GitHub 계정에 게시했다고 보도한 후, 미국 상하원 의원들이 사이버보안 및 인프라 보안국(CISA)에 답변을 요구하고 있습니다. 민감한 자격 증명과 데이터를 노출한 이 침해 사고는 기관의 보안 관행에 우려를 표명한 의원들의 긴급한 문의를 촉발했습니다.

{{< ad-banner >}}

CISA는 현재 침해 사고를 통제하고 유출된 자격 증명을 무효화하기 위해 노력하고 있습니다. 이 사건은 민감한 시스템에 대한 계약업체 접근과 관련된 위험과 클라우드 환경, 특히 정부 기관이 사용하는 환경을 보호하는 데 따르는 어려움을 강조합니다. 기관은 아직 노출된 데이터의 전체 범위나 관련 계약업체의 신원을 공개하지 않았습니다.

{{< netrunner-insight >}}

이번 사건은 클라우드 환경에서 계약업체 활동에 대한 엄격한 접근 통제와 지속적인 모니터링의 중요성을 강조합니다. SOC 분석가는 GitHub 저장소에서 유출된 자격 증명을 감사하고 자동화된 비밀 스캐닝 도구를 구현하는 데 우선순위를 두어야 합니다. DevSecOps 팀은 최소 권한 접근을 적용하고 노출이 의심되는 즉시 모든 클라우드 키를 교체해야 합니다.

{{< /netrunner-insight >}}

---

**[Krebs on Security에서 전체 기사 읽기 ›](https://krebsonsecurity.com/2026/05/lawmakers-demand-answers-as-cisa-tries-to-contain-data-leak/)**
