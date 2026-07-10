---
title: "Ill Bloom 결함, 취약한 복구 구문으로 암호화폐 지갑에서 310만 달러 탈취"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "ko"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "공격자들이 Ill Bloom으로 명명된 암호화폐 지갑 복구 구문 생성의 취약점을 악용하여 조직적인 공격으로 310만 달러를 탈취했습니다."
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "암호화폐 지갑"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

공격자들이 Ill Bloom으로 명명된 암호화폐 지갑 복구 구문 생성의 취약점을 악용하여 조직적인 공격으로 310만 달러를 탈취했습니다.

{{< cyber-report severity="High" source="The Hacker News" target="암호화폐 지갑" >}}

보안 업체 Coinspect가 Ill Bloom이라는 암호화폐 지갑 소프트웨어의 취약점을 공개했습니다. 이 취약점은 복구 구문 생성 시 약한 무작위성을 악용하여 공격자가 자금을 탈취할 수 있게 합니다. 이 결함은 일부 지갑이 지갑 자금에 대한 접근을 제어하는 니모닉 구문을 생성하는 방식에 영향을 미칩니다. 무작위성이 충분하지 않을 경우 공격자는 구문을 계산하여 지갑에 대한 완전한 제어권을 얻을 수 있습니다.

{{< ad-banner >}}

Coinspect는 공격자들이 이미 5월에 조직적인 공격으로 이 취약점을 악용하여 여러 지갑에서 약 310만 달러를 탈취했다고 확인했습니다. 공격의 정확한 날짜와 전체 범위는 공개되지 않았지만, 이 사건은 암호화 애플리케이션에서 안전한 난수 생성의 중요성을 강조합니다.

지갑 사용자는 자신의 소프트웨어가 암호학적으로 안전한 난수 생성기를 사용하는지 확인하고, 감사된 무작위성 구현을 갖춘 지갑으로 자금을 이전하는 것을 고려해야 합니다. 개발자는 엔트로피 소스를 검토하고 BIP39와 같은 업계 표준을 준수해야 합니다.

{{< netrunner-insight >}}

이번 사건은 암호화 키 생성에서 약한 엔트로피에 의존하는 위험성을 강조합니다. SOC 분석가는 비정상적인 지갑 거래나 대량 자금 이동을 모니터링해야 하며, DevSecOps 엔지니어는 보안이 중요한 애플리케이션의 모든 난수 생성을 감사해야 합니다. 예측 가능한 무작위성은 항상 악용될 것이라고 가정하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
