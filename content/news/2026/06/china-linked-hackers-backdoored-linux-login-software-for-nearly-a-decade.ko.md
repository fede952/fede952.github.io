---
title: "중국 연계 해커, 거의 10년 동안 리눅스 로그인 소프트웨어에 백도어 설치"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "ko"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "Velvet Ant로 알려진 중국 연계 그룹이 PAM 및 OpenSSH 구성 요소를 손상시켜 거의 10년 동안 탐지되지 않고 리눅스 로그인 시스템에 숨어 있었습니다."
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "리눅스 로그인 시스템 (PAM, OpenSSH)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Velvet Ant로 알려진 중국 연계 그룹이 PAM 및 OpenSSH 구성 요소를 손상시켜 거의 10년 동안 탐지되지 않고 리눅스 로그인 시스템에 숨어 있었습니다.

{{< cyber-report severity="High" source="The Hacker News" target="리눅스 로그인 시스템 (PAM, OpenSSH)" >}}

Velvet Ant로 추적되는 중국 연계 위협 행위자가 PAM(Pluggable Authentication Modules) 및 OpenSSH를 포함한 핵심 리눅스 로그인 구성 요소에 백도어를 설치하여 거의 10년 동안 지속적인 접근을 유지한 것으로 밝혀졌습니다. 이 그룹은 인증 스택 깊숙이 백도어를 삽입하여 표준 정리 절차에 저항하도록 만든 네트워크를 표적으로 삼았습니다.

{{< ad-banner >}}

보안 회사 Sygnia에 따르면, 공격자는 로그인 소프트웨어에 대한 신뢰를 악용하여 탐지를 피했습니다. 사용자 접근을 제어하는 메커니즘 자체를 수정함으로써 시스템 업데이트와 일상적인 보안 검사에서도 발판이 살아남도록 했습니다. 이 캠페인은 국가 지원 그룹이 기반 인프라를 표적으로 삼는 데 있어 점점 더 정교해지고 있음을 강조합니다.

이번 침해는 조직이 일반적인 엔드포인트 탐지 이상으로 중요한 시스템 구성 요소의 무결성을 모니터링해야 할 필요성을 강조합니다. 방어자는 PAM 모듈 및 SSH 바이너리에 대한 파일 무결성 모니터링과 인증 로그의 행동 분석을 통해 백도어가 설치된 로그인 프로세스를 나타내는 이상 징후를 발견하는 것을 고려해야 합니다.

{{< netrunner-insight >}}

SOC 분석가와 DevSecOps 팀에게 이는 공격자가 인증 계층 자체를 표적으로 삼고 있다는 뚜렷한 경고입니다. PAM 및 OpenSSH 바이너리에 대한 런타임 무결성 검사를 구현하고, 변조를 탐지하기 위해 커널 수준 모니터링을 고려하십시오. 또한, 사고 대응 플레이북의 일환으로 SSH 키 기반 인증 및 PAM 구성 변경 사항을 검토하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
