---
title: "OpenAI Codex 인증 토큰, npm 공급망 공격으로 탈취"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "ko"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "악성 npm 패키지 codexui-android가 개발자를 표적으로 삼아 OpenAI Codex 인증 토큰을 탈취하며, 주간 다운로드 수 29,000건 이상을 기록했습니다."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "OpenAI Codex 개발자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

악성 npm 패키지 codexui-android가 개발자를 표적으로 삼아 OpenAI Codex 인증 토큰을 탈취하며, 주간 다운로드 수 29,000건 이상을 기록했습니다.

{{< cyber-report severity="High" source="The Hacker News" target="OpenAI Codex 개발자" >}}

사이버보안 연구원들이 OpenAI Codex를 사용하는 개발자를 표적으로 한 악성 공급망 캠페인을 발견했습니다. 이 공격은 합법적으로 보이는 npm 패키지 codexui-android를 이용하며, 이 패키지는 GitHub와 npm 모두에서 OpenAI Codex용 원격 웹 UI로 광고됩니다. 이 패키지는 주간 다운로드 수 29,000건 이상을 기록하며 개발자 커뮤니티 내에서 상당한 영향력을 보여줍니다.

{{< ad-banner >}}

악성 패키지는 의심하지 않는 개발자로부터 OpenAI Codex 인증 토큰을 탈취하도록 설계되었습니다. 보고 시점 기준으로 이 패키지는 여전히 다운로드 가능하여 지속적인 위협이 되고 있습니다. codexui-android를 설치한 개발자는 즉시 토큰을 교체하고 시스템에서 무단 액세스를 감사할 것을 권고합니다.

이번 사건은 오픈소스 생태계에서 공급망 공격의 지속적인 위험을 강조합니다. 합법적으로 들리는 패키지 이름과 높은 다운로드 수는 개발자에게 잘못된 안전감을 심어줄 수 있습니다. 조직은 엄격한 패키지 검증 프로세스를 구현하고 비정상적인 패키지 동작을 탐지하는 도구 사용을 고려해야 합니다.

{{< netrunner-insight >}}

SOC 분석가와 DevSecOps 엔지니어에게 이 공격은 npm 패키지 다운로드 및 동작을 모니터링해야 할 필요성을 강조합니다. 예상치 못한 토큰 유출에 대한 런타임 탐지를 구현하고 API 토큰에 대한 최소 권한 액세스를 적용하세요. 소프트웨어 공급망을 정기적으로 감사하고 패키지 무결성 검증 도구 사용을 고려하세요.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
