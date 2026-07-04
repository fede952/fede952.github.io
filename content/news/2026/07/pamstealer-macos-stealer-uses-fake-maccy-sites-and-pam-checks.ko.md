---
title: "PamStealer macOS 스틸러, 가짜 Maccy 사이트와 PAM 검사 활용"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "ko"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs가 가짜 Maccy 사이트를 통해 유포되는 macOS 정보 스틸러 PamStealer를 발견했습니다. 이 스틸러는 PAM 검사를 사용하여 로그인 비밀번호를 탈취합니다."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "macOS 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs가 가짜 Maccy 사이트를 통해 유포되는 macOS 정보 스틸러 PamStealer를 발견했습니다. 이 스틸러는 PAM 검사를 사용하여 로그인 비밀번호를 탈취합니다.

{{< cyber-report severity="High" source="The Hacker News" target="macOS 사용자" >}}

Jamf Threat Labs의 사이버보안 연구원들이 PamStealer라는 새로운 macOS 정보 스틸러를 식별했습니다. 이 악성코드는 합법적인 오픈소스 클립보드 관리자인 Maccy로 위장한 컴파일된 AppleScript(.scpt) 파일로 유포됩니다. 로그인 비밀번호를 포함한 민감한 데이터를 빼내기 위해 교묘한 트릭을 사용합니다.

{{< ad-banner >}}

PamStealer는 macOS의 PAM(Pluggable Authentication Module) 프레임워크를 악용하는 능력에서 이름을 얻었습니다. 인증 프로세스를 가로채어 사용자가 로그인하거나 권한이 필요한 작업을 인증할 때 자격 증명을 캡처합니다. 그런 다음 탈취한 데이터를 공격자가 제어하는 서버로 유출합니다.

이 캠페인은 가짜 웹사이트와 사회공학 기법에 의존하여 사용자가 악성 .scpt 파일을 다운로드하도록 속입니다. 실행되면 악성코드는 의심을 피하기 위해 PAM 검사를 수행하여 비밀번호를 수집합니다. macOS 엔드포인트를 보유한 조직은 비정상적인 .scpt 파일 실행 및 PAM 관련 이상 징후를 모니터링해야 합니다.

{{< netrunner-insight >}}

SOC 분석가에게 이는 macOS 엔드포인트에서 컴파일된 AppleScript 실행 및 PAM 수정을 모니터링해야 함을 강조합니다. DevSecOps 팀은 애플리케이션 허용 목록을 적용하고 사용자에게 특히 클립보드 관리자와 같은 소프트웨어 출처를 확인하도록 교육해야 합니다. PAM 남용에 대한 엔드포인트 탐지 규칙을 구현하면 이 스틸러를 조기에 발견하는 데 도움이 될 수 있습니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
