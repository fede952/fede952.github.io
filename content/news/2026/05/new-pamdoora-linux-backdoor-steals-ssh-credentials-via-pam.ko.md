---
title: "새로운 PamDOORa 리눅스 백도어, PAM을 통해 SSH 자격 증명 탈취"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "ko"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "PamDOORa라는 이름의 새로운 리눅스 백도어가 러시아 사이버 범죄 포럼에서 1,600달러에 판매되고 있습니다. 이 백도어는 PAM 모듈을 사용하여 매직 패스워드와 TCP 포트 조합으로 지속적인 SSH 접근을 제공합니다."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "리눅스 SSH 서버"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PamDOORa라는 이름의 새로운 리눅스 백도어가 러시아 사이버 범죄 포럼에서 1,600달러에 판매되고 있습니다. 이 백도어는 PAM 모듈을 사용하여 매직 패스워드와 TCP 포트 조합으로 지속적인 SSH 접근을 제공합니다.

{{< cyber-report severity="High" source="The Hacker News" target="리눅스 SSH 서버" >}}

사이버 보안 연구원들이 'darkworm'으로 알려진 위협 행위자가 Rehub 러시아 사이버 범죄 포럼에서 1,600달러에 광고한 PamDOORa라는 새로운 리눅스 백도어를 발견했습니다. 이 백도어는 PAM(Pluggable Authentication Module) 기반의 사후 침투 도구 키트로 설계되어, 매직 패스워드와 특정 TCP 포트 조합을 통해 지속적인 SSH 접근을 가능하게 합니다.

{{< ad-banner >}}

PamDOORa는 악성 PAM 모듈을 통해 SSH 인증을 가로채어 공격자가 정상 자격 증명을 우회하고 무단 접근을 얻을 수 있게 합니다. PAM 모듈을 사용함으로써 백도어는 리눅스 시스템의 표준 인증 흐름에 통합되어 은밀하게 작동합니다.

사이버 범죄 포럼에서 이러한 도구의 판매는 정교한 공격 도구의 상품화가 계속되고 있음을 보여줍니다. 조직은 비정상적인 SSH 인증 패턴을 모니터링하고 PAM 구성이 정기적으로 감사되도록 해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, PamDOORa 탐지를 위해 비표준 포트에서의 예상치 못한 SSH 연결을 모니터링하고 PAM 모듈 변경 사항과 연관 지어야 합니다. DevSecOps 팀은 엄격한 PAM 구성 관리를 시행하고 /etc/pam.d/ 및 관련 라이브러리에 대한 파일 무결성 모니터링을 고려해야 합니다. 이 백도어는 PAM을 중요한 보안 경계로 취급해야 함을 강조합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
