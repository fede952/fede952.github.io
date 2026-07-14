---
title: "CISA GitHub 유출로 AWS GovCloud 키 6개월간 노출"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "ko"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "계약자가 CISA의 내부 자격 증명( AWS GovCloud 키 포함)을 GitHub에 6개월간 유출했습니다. 전문가들은 보안 팀을 위한 중요한 교훈을 강조합니다."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA GitHub 저장소"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

계약자가 CISA의 내부 자격 증명( AWS GovCloud 키 포함)을 GitHub에 6개월간 유출했습니다. 전문가들은 보안 팀을 위한 중요한 교훈을 강조합니다.

{{< cyber-report severity="High" source="Krebs on Security" target="CISA GitHub 저장소" >}}

사이버보안 및 인프라 보안국(CISA)은 계약자가 실수로 수십 개의 내부 자격 증명( AWS GovCloud 키 포함)을 공개 GitHub 저장소에 게시한 데이터 유출을 공개했습니다. 해당 자격 증명은 KrebsOnSecurity가 기관에 통보하기 전까지 거의 6개월간 노출된 상태로 남아 있었습니다.

{{< ad-banner >}}

CISA의 사후 분석 결과, 초기 대응에서 탐지 지연 및 공개 저장소 내 비밀 자동 스캔 부재 등의 문제점이 확인되었습니다. 이 사건은 강력한 비밀 관리와 코드 저장소의 지속적인 모니터링의 필요성을 강조합니다.

전문가들은 사전 커밋 훅, 정기적인 비밀 스캔, 엄격한 접근 통제를 구현하여 유사한 유출을 방지할 것을 권장합니다. 임시 자격 증명 사용과 자동 교체는 노출된 키의 영향을 완화할 수 있습니다.

{{< netrunner-insight >}}

이번 사건은 비밀 스캔이 커밋 후뿐만 아니라 CI/CD 파이프라인에 통합되어야 하는 전형적인 사례입니다. SOC 분석가는 공개 저장소 노출에 대한 경고를 우선 처리해야 하며, DevSecOps 팀은 계약자에 대한 최소 권한 접근을 강화해야 합니다. 자격 증명 교체를 자동화하고 GitLeaks 또는 TruffleHog와 같은 도구를 사용하여 초기에 유출을 발견하는 것을 고려하십시오.

{{< /netrunner-insight >}}

---

**[Krebs on Security에서 전체 기사 읽기 ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
