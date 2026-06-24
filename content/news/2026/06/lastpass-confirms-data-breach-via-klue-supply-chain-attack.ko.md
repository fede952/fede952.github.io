---
title: "LastPass, Klue 공급망 공격을 통한 데이터 유출 확인"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "ko"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass는 공격자가 타사 앱 Klue에서 OAuth 토큰을 탈취하여 Salesforce 환경의 고객 데이터에 접근했다고 공개했습니다."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "LastPass Salesforce 환경"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass는 공격자가 타사 앱 Klue에서 OAuth 토큰을 탈취하여 Salesforce 환경의 고객 데이터에 접근했다고 공개했습니다.

{{< cyber-report severity="High" source="BleepingComputer" target="LastPass Salesforce 환경" >}}

LastPass는 이달 초 Klue 공급망 공격에서 회사의 OAuth 토큰을 탈취한 해커가 Salesforce 환경의 고객 데이터에 접근했다고 확인했습니다. 2026년 6월 23일에 공개된 이 침해 사고는 타사 통합 및 토큰 탈취의 위험성을 강조합니다.

{{< ad-banner >}}

공격자는 타사 애플리케이션인 Klue의 손상된 OAuth 토큰을 사용하여 LastPass의 Salesforce 인스턴스에 무단 접근했습니다. 이 공급망 공격으로 위협 행위자는 일반적인 인증 알림을 트리거하지 않고 고객 데이터를 유출할 수 있었습니다.

LastPass는 영향을 받은 고객에게 통보하고 손상된 토큰을 취소했습니다. 또한 회사는 유사한 사고를 방지하기 위해 타사 접근 정책을 검토 중입니다. 이번 침해 사고는 OAuth 토큰 사용 모니터링과 통합 서비스에 대한 엄격한 접근 통제의 중요성을 강조합니다.

{{< netrunner-insight >}}

이번 사건은 OAuth 토큰 남용을 통한 공급망 위험의 전형적인 예입니다. SOC 분석가는 비정상적인 토큰 사용 모니터링과 토큰 만료 정책 구현을 최우선으로 해야 합니다. DevSecOps 팀은 타사 통합에 대해 최소 권한 접근을 적용하고 폭발 반경을 줄이기 위해 단기 토큰 사용을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
