---
title: "손상된 joyfill npm 패키지, Node.js 프로젝트에 RAT 유포"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "ko"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "@joyfill/layouts 및 @joyfill/components의 베타 버전에 암호화된 코드를 해석하여 원격 접근 트로이 목마를 배포하는 임포트 타임 자바스크립트 임플란트가 포함되어 있습니다."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "joyfill 패키지를 사용하는 Node.js 개발자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

@joyfill/layouts 및 @joyfill/components의 베타 버전에 암호화된 코드를 해석하여 원격 접근 트로이 목마를 배포하는 임포트 타임 자바스크립트 임플란트가 포함되어 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="joyfill 패키지를 사용하는 Node.js 개발자" >}}

@joyfill 네임스페이스의 두 npm 패키지, @joyfill/layouts 버전 0.1.2-2773.beta.0 및 @joyfill/components 버전 4.0.0-rc24-2773-beta.4가 손상되었습니다. 이 베타 릴리스에는 암호화된 코드를 해석하여 DEV#POPPER 악성코드 패밀리와 관련된 원격 접근 트로이 목마(RAT)를 최종적으로 전달하는 임포트 타임 자바스크립트 임플란트가 포함되어 있습니다.

{{< ad-banner >}}

악성 코드는 패키지가 Node.js 프로젝트에 임포트될 때 실행되어 공격자가 손상된 시스템에 원격으로 접근할 수 있게 합니다. 이 공격은 npm 생태계를 대상으로 한 공급망 공격의 지속적인 위험을 강조하며, 특히 덜 주목받을 수 있는 베타 또는 릴리스 후보 버전을 통해 이루어집니다.

이 특정 버전을 사용한 개발자는 즉시 자격 증명을 교체하고, 침해 지표를 스캔하며, 의존성 트리에서 다른 의심스러운 패키지를 검토해야 합니다. npm 레지스트리는 악성 버전을 제거했을 가능성이 높지만, 기존 설치본은 여전히 위협이 됩니다.

{{< netrunner-insight >}}

이 사건은 사전 릴리스 패키지를 면밀히 조사하고 의존성 무결성 검사를 구현하는 것의 중요성을 강조합니다. SOC 분석가는 Node.js 애플리케이션에서 비정상적인 아웃바운드 연결을 모니터링해야 하며, DevSecOps 팀은 엄격한 버전 고정을 시행하고 npm audit 또는 SCA 스캐너와 같은 도구를 사용하여 알려진 악성 패키지를 탐지해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
