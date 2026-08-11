---
title: "BdThemes 공급망 공격으로 악성 WordPress 관리자 계정 생성"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "ko"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "공급망 침해가 BdThemes WordPress 플러그인에 발생했습니다. 소스 코드는 전혀 수정되지 않았지만, 악성 JSON이 불법 관리자 계정을 생성합니다."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "BdThemes 플러그인을 사용하는 WordPress 사이트"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

공급망 침해가 BdThemes WordPress 플러그인에 발생했습니다. 소스 코드는 전혀 수정되지 않았지만, 악성 JSON이 불법 관리자 계정을 생성합니다.

{{< cyber-report severity="High" source="The Hacker News" target="BdThemes 플러그인을 사용하는 WordPress 사이트" >}}

사이버 보안 연구원들이 WordPress 플러그인 공급업체인 BdThemes를 대상으로 한 공급망 공격을 공개했습니다. 이 침해로 인해 WordPress 플러그인 팀이 플러그인 다운로드를 일시적으로 중단했습니다. 특히 이 공격은 일반적인 공급망 사고와 달리 공식 WordPress.org 저장소의 소스 코드 파일이 수정되지 않았습니다.

{{< ad-banner >}}

대신 이 공격은 악성 JSON 페이로드를 이용해 불법 WordPress 관리자 계정을 생성합니다. 이 기술을 통해 공격자는 핵심 플러그인 파일을 변경하지 않고도 영향을 받는 사이트에 무단 액세스할 수 있어, 표준 무결성 검사로 탐지하기가 더 어렵습니다.

Wordfence 연구원 Paolo Tresso는 이 공격의 비정상적인 특성을 강조하며, 소스 코드 수정이 없다는 점이 코드 무결성 이상의 포괄적인 공급망 모니터링의 필요성을 강조한다고 밝혔습니다.

{{< netrunner-insight >}}

이 공격은 코드 변경뿐만 아니라 JSON과 같은 구성 및 데이터 파일도 모니터링하는 것의 중요성을 강조합니다. SOC 분석가에게 플러그인 업데이트는 고위험 이벤트로 취급하고 소스 코드뿐만 아니라 모든 파일의 무결성을 검증해야 합니다. DevSecOps는 예상치 못한 관리자 계정 생성에 대한 런타임 모니터링을 구현하고 코드가 아닌 자산을 포함하는 파일 무결성 모니터링을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
