---
title: "Polymarket, 서드파티 공급업체를 통한 공급망 공격으로 300만 달러 손실"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "ko"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "해커들이 서드파티 공급업체를 침해한 후 Polymarket의 프론트엔드에 악성 스크립트를 주입하여 고객에게 300만 달러의 손실을 입혔습니다. 플랫폼은 피해자에게 전액 보상할 예정입니다."
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Polymarket 프론트엔드 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

해커들이 서드파티 공급업체를 침해한 후 Polymarket의 프론트엔드에 악성 스크립트를 주입하여 고객에게 300만 달러의 손실을 입혔습니다. 플랫폼은 피해자에게 전액 보상할 예정입니다.

{{< cyber-report severity="High" source="BleepingComputer" target="Polymarket 프론트엔드 사용자" >}}

탈중앙화 예측 시장 플랫폼 Polymarket은 공격자들이 서드파티 공급업체를 침해하여 프론트엔드에 악성 스크립트를 주입했으며, 이로 인해 고객이 약 300만 달러의 손실을 입었다고 밝혔습니다. 공급망 공격으로 설명된 이 사건은 플랫폼의 사용자 인터페이스를 표적으로 삼아 자금을 빼돌렸습니다.

{{< ad-banner >}}

회사는 영향을 받은 고객에게 전액 보상할 것이라고 밝혔지만, 정확한 피해자 수는 공개되지 않았습니다. 이번 침해 사고는 프론트엔드 무결성이 거래 보안에 중요한 DeFi 및 암호화폐 플랫폼에서 서드파티 의존성과 관련된 위험을 강조합니다.

특정 CVE나 CVSS 점수는 제공되지 않았지만, 공급업체를 침해하여 프론트엔드 코드를 변경하는 공격 벡터는 코드 서명, 무결성 검사, 공급업체 위험 평가 등 강력한 공급망 보안 조치의 필요성을 강조합니다.

{{< netrunner-insight >}}

이번 사건은 프론트엔드 무결성을 표적으로 한 전형적인 공급망 공격입니다. SOC 분석가는 서드파티 라이브러리나 CDN에 의존하는 웹 애플리케이션에서 무단 스크립트 주입을 모니터링해야 합니다. DevSecOps 팀은 이러한 위험을 완화하기 위해 엄격한 콘텐츠 보안 정책(CSP), 하위 리소스 무결성(SRI) 검사, 정기적인 공급업체 감사를 시행해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
