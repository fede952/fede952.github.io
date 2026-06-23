---
title: "PostCSS 도구로 위장한 악성 npm 패키지, Windows RAT 유포"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "ko"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "PostCSS 도구로 위장한 세 개의 악성 npm 패키지가 Windows 원격 접근 트로이목마를 유포하는 것으로 확인되었습니다. 연구진은 npm 패키지 설치 시 주의를 당부했습니다."
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "npm 사용자, Windows 시스템"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PostCSS 도구로 위장한 세 개의 악성 npm 패키지가 Windows 원격 접근 트로이목마를 유포하는 것으로 확인되었습니다. 연구진은 npm 패키지 설치 시 주의를 당부했습니다.

{{< cyber-report severity="High" source="The Hacker News" target="npm 사용자, Windows 시스템" >}}

사이버보안 연구진이 Windows 기반 원격 접근 트로이목마(RAT)를 유포하도록 설계된 세 개의 악성 npm 패키지(aes-decode-runner-pro, postcss-minify-selector, postcss-minify-selector-parser)를 식별했습니다. 이 패키지들은 지난 한 달 동안 한 npm 사용자에 의해 게시되었으며 총 1,016회 다운로드되어 중간 수준이지만 우려할 만한 배포를 보였습니다.

{{< ad-banner >}}

이 패키지들은 널리 사용되는 CSS 후처리기인 PostCSS 도구로 위장하여 개발자들을 속여 설치하게 합니다. 설치되면 악성 코드가 페이로드를 실행하여 감염된 Windows 시스템에 원격 접근을 설정하며, 공격자가 데이터를 유출하거나 추가 악성코드를 설치하거나 네트워크 내에서 측면 이동을 할 수 있습니다.

이번 사건은 npm 생태계에서의 타이포스쿼팅과 의존성 혼란의 지속적인 위협을 강조합니다. 개발자들은 패키지 이름을 신중히 확인하고, 설치 전에 소스 코드를 검토하며, 패키지 무결성 검증 도구를 사용하여 이러한 위험을 완화해야 합니다.

{{< netrunner-insight >}}

SOC 분석가와 DevSecOps 엔지니어에게 이는 엄격한 패키지 출처 확인을 시행하고 비정상적인 npm 패키지 설치를 모니터링하라는 상기입니다. 알려진 악성 패키지에 대한 자동 스캔을 구현하고 개발자들에게 패키지 이름을 맹목적으로 신뢰하는 위험에 대해 교육하는 것을 고려하십시오. 상대적으로 낮은 다운로드 수는 이 캠페인이 초기 단계일 수 있음을 시사하므로 유사한 패키지에 대한 사전 탐색이 필요합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
