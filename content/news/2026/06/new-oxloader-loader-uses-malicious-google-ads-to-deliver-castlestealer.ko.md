---
title: "새로운 OXLOADER 로더, 악성 Google Ads를 이용해 CastleStealer 유포"
date: "2026-06-23T10:32:59Z"
original_date: "2026-06-22T13:20:12"
lang: "ko"
translationKey: "new-oxloader-loader-uses-malicious-google-ads-to-deliver-castlestealer"
author: "NewsBot (Validated by Federico Sella)"
description: "Elastic Security Labs가 악성 Google Ads를 통해 OXLOADER 로더를 배포하는 캠페인을 공개했습니다. 이 로더는 CastleStealer 악성코드를 전달하며, 러시아어를 사용하는 위협 행위자가 운영할 가능성이 있습니다."
original_url: "https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html"
source: "The Hacker News"
severity: "High"
target: "악성 Google Ads를 클릭하는 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Elastic Security Labs가 악성 Google Ads를 통해 OXLOADER 로더를 배포하는 캠페인을 공개했습니다. 이 로더는 CastleStealer 악성코드를 전달하며, 러시아어를 사용하는 위협 행위자가 운영할 가능성이 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="악성 Google Ads를 클릭하는 사용자" >}}

Elastic Security Labs의 사이버보안 연구원들이 악성 Google Ads를 이용해 이전에 보고되지 않은 OXLOADER라는 악성코드 로더를 유포하는 새로운 캠페인을 발견했습니다. 이 로더는 자격 증명을 탈취하는 악성코드인 CastleStealer를 의심하지 않는 피해자에게 전달하는 데 사용됩니다.

{{< ad-banner >}}

이 캠페인은 금전적 동기에 의해 이루어지며, 러시아어를 사용하는 위협 행위자가 운영할 가능성이 있습니다. 초기 감염 경로로 Google Ads를 사용하는 것은 사이버 범죄자들이 전통적인 보안 조치를 우회하고 더 넓은 대중에게 도달하기 위해 진화하는 전술을 강조합니다.

조직과 개인은 겉보기에 합법적인 출처의 광고라도 클릭할 때 주의를 기울이는 것이 좋습니다. 광고 차단기를 구현하고 최신 보안 소프트웨어를 유지하면 이러한 공격의 위험을 완화하는 데 도움이 될 수 있습니다.

{{< netrunner-insight >}}

SOC 분석가에게는 비정상적인 광고 클릭과 이후 알 수 없는 도메인으로의 네트워크 연결을 모니터링하는 것이 중요합니다. DevSecOps 팀은 프록시 필터에서 광고 관련 도메인을 차단하고 신뢰할 수 있는 검색 엔진의 광고라도 클릭 위험에 대해 사용자에게 교육하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html)**
