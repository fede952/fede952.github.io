---
title: "Klue OAuth 침해: Icarus 해커, Salesforce 토큰 탈취"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "ko"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue, Salesforce 통합에 영향을 미치는 OAuth 토큰 도난 확인; Icarus 갈취 그룹이 책임 주장하며 피해자 목록 증가"
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "Klue 시장 인텔리전스 플랫폼"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue, Salesforce 통합에 영향을 미치는 OAuth 토큰 도난 확인; Icarus 갈취 그룹이 책임 주장하며 피해자 목록 증가

{{< cyber-report severity="High" source="BleepingComputer" target="Klue 시장 인텔리전스 플랫폼" >}}

시장 인텔리전스 플랫폼 Klue가 고객의 Salesforce 환경에 연결하는 데 사용되는 OAuth 토큰이 도난당한 보안 사고를 확인했습니다. 새로 등장한 'Icarus' 갈취 그룹이 주장한 이 침해로 인해 영향을 받은 피해자 목록이 확대되고 있습니다.

{{< ad-banner >}}

도난당한 OAuth 토큰을 통해 공격자는 추가 인증 없이 Salesforce 데이터에 접근할 수 있어 Klue 고객에게 심각한 위험을 초래합니다. 이 사건은 OAuth 토큰 노출의 위험성과 강력한 토큰 수명 주기 관리의 필요성을 강조합니다.

Icarus 그룹이 공개적으로 공격을 주장함에 따라, Klue의 Salesforce 통합을 사용하는 조직은 즉시 관련 OAuth 토큰을 폐기하고 교체해야 하며 무단 접근을 모니터링해야 합니다. 침해의 전체 범위는 여전히 조사 중입니다.

{{< netrunner-insight >}}

이번 사건은 OAuth 토큰을 민감한 자격 증명으로 보호하는 것이 얼마나 중요한지 강조합니다. SOC 분석가는 비정상적인 Salesforce API 호출을 모니터링하고 토큰 만료 정책을 시행하는 데 우선순위를 두어야 합니다. DevSecOps 팀은 손상 시 피해 범위를 제한하기 위해 엄격한 토큰 범위 지정 및 교체 메커니즘을 구현해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
