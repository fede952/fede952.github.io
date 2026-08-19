---
title: "오타를 이용한 RubyGems 패키지가 브라우저 자격 증명과 암호화폐 지갑을 탈취한다"
date: "2026-08-19T07:36:21Z"
original_date: "2026-08-18T11:20:00"
lang: "ko"
translationKey: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
slug: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
author: "NewsBot (Validated by Federico Sella)"
description: "연구원들은 Windows 기반 정보 탈취기를 배포하는 16개의 오타를 이용한 RubyGems 패키지를 발견했으며, 브라우저 자격 증명과 암호화폐 지갑을 노리고 있습니다."
original_url: "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
source: "The Hacker News"
severity: "High"
target: "Windows 사용자의 RubyGems 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

연구원들은 Windows 기반 정보 탈취기를 배포하는 16개의 오타를 이용한 RubyGems 패키지를 발견했으며, 브라우저 자격 증명과 암호화폐 지갑을 노리고 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="Windows 사용자의 RubyGems 사용자" >}}

사이버 보안 연구원들은 RubyGems 사용자를 대상으로 하는 새로운 오타 스쿼팅 캠페인을 발견했으며, Windows 기반 정보 탈취기를 배포하고 있습니다. StubMaker로 추적되는 이 캠페인은 2026년 8월 15일 OpenSourceMalware에 의해 발견되었으며, 브라우저 자격 증명과 암호화폐 지갑을 탈취하도록 설계된 16개의 악성 패키지를 포함합니다.

{{< ad-banner >}}

악성 패키지에는 'ubnuler', 'ubnlder', 'ri18nr', 'reaker', 'rakier', 'orakw', 'joxn'과 같은 이름이 포함되어 있으며, 인기 있는 gem의 오타를 이용해 개발자가 설치하도록 속일 가능성이 높습니다. 일단 설치되면, 이 탈취기는 브라우저와 암호화폐 지갑 확장 프로그램에서 민감한 데이터를 수집하여 상당한 공급망 위험을 초래합니다.

이 캠페인은 오픈 소스 생태계에서 오타 스쿼팅의 지속적인 위협을 강조합니다. 개발자는 패키지 이름을 신중하게 확인하고, 신뢰할 수 있는 소스를 사용하며, 프로젝트에서 의심스러운 종속성을 모니터링하는 것이 좋습니다.

{{< netrunner-insight >}}

SOC 분석가에게 이 캠페인은 예상치 못한 RubyGems 설치와 의심스러운 도메인으로의 네트워크 호출을 모니터링해야 함을 강조합니다. DevSecOps 엔지니어는 엄격한 종속성 고정을 시행하고 오타 스쿼팅 패키지를 스캔하는 도구를 사용해야 합니다. 또한 알려진 악성 패키지 이름을 차단하고 개발자에게 오타 스쿼팅 위험에 대해 교육하는 것을 고려하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)**
