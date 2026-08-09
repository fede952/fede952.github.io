---
title: "CSS 공격이 이메일 경계를 벗어나 비밀번호와 토큰을 탈취한다"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "ko"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "새로운 연구에 따르면 CSS 기반 공격이 이메일 콘텐츠의 경계를 벗어나 웹메일 인터페이스를 하이재킹하여 주요 제공업체 전반에서 자격 증명과 토큰을 탈취할 수 있습니다."
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "웹메일 인터페이스(Outlook, Gmail 등)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

새로운 연구에 따르면 CSS 기반 공격이 이메일 콘텐츠의 경계를 벗어나 웹메일 인터페이스를 하이재킹하여 주요 제공업체 전반에서 자격 증명과 토큰을 탈취할 수 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="웹메일 인터페이스(Outlook, Gmail 등)" >}}

보안 연구원 Gareth(PortSwigger 소속)는 CSS를 활용하여 이메일 콘텐츠와 주변 웹메일 인터페이스 간의 의도된 격리를 깨는 새로운 공격 클래스를 발견했습니다. 악성 이메일을 조작함으로써 공격자는 콘텐츠가 메시지 경계를 벗어나 웹메일 자체 UI를 방해하도록 만들 수 있으며, 잠재적으로 비밀번호를 캡처하고 세션 토큰을 탈취하며 신뢰할 수 있는 사용자 작업을 하이재킹할 수 있습니다.

{{< ad-banner >}}

이 연구는 Outlook, Gmail, Fastmail, Proton Mail, Yahoo Mail 및 AOL Mail을 포함한 주요 웹메일 제공업체에 영향을 미치는 공격 체인을 입증합니다. 자격 증명 탈취 외에도 이러한 기술은 제3자 계정을 장악하고, 민감한 토큰을 유출하며, 이메일을 읽는 AI 도구를 조작하는 데 사용될 수 있어 공격 표면이 크게 확장됩니다.

이러한 발견은 웹메일 클라이언트가 신뢰할 수 없는 콘텐츠를 렌더링하는 방식의 근본적인 약점을 강조합니다. 아직 특정 CVE가 할당되지는 않았지만 영향은 심각하며, 웹메일에 의존하는 조직은 업데이트를 모니터링하고 잠재적 악용을 완화하기 위해 추가 보안 계층을 고려해야 합니다.

{{< netrunner-insight >}}

이 연구는 이메일이 단순히 악성코드의 경로일 뿐만 아니라 사용자가 신뢰하는 인터페이스 자체에 대한 무기가 될 수 있음을 강조합니다. SOC 분석가는 의심스러운 이메일을 단순한 피싱 미끼가 아닌 UI를 깨뜨릴 수 있는 페이로드로 취급해야 합니다. DevSecOps 팀은 웹메일 클라이언트가 콘텐츠를 샌드박싱하는 방식을 검토하고 CSS 기반 탈출 시도를 제한하기 위해 엄격한 CSP(Content Security Policy) 헤더를 적용하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
