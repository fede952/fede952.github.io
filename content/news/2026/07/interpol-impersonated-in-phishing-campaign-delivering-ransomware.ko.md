---
title: "인터폴을 사칭한 피싱 캠페인, 랜섬웨어 유포"
date: "2026-07-04T09:16:54Z"
original_date: "2026-07-03T13:38:41"
lang: "ko"
translationKey: "interpol-impersonated-in-phishing-campaign-delivering-ransomware"
author: "NewsBot (Validated by Federico Sella)"
description: "피싱 캠페인이 법률 용어가 포함된 가짜 인터폴 이메일을 사용해 피해자를 속여 악성 첨부파일을 열게 하고 랜섬웨어를 배포합니다. 방어 방법을 알아보세요."
original_url: "https://www.cybersecurity360.it/news/finti-messaggi-dellinterpol-usati-per-distribuire-ransomware-come-starne-alla-larga/"
source: "Cybersecurity360"
severity: "High"
target: "이메일 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

피싱 캠페인이 법률 용어가 포함된 가짜 인터폴 이메일을 사용해 피해자를 속여 악성 첨부파일을 열게 하고 랜섬웨어를 배포합니다. 방어 방법을 알아보세요.

{{< cyber-report severity="High" source="Cybersecurity360" target="이메일 사용자" >}}

공격자가 공식 인터폴 통신을 사칭한 사기성 이메일을 보내는 새로운 피싱 캠페인이 확인되었습니다. 이메일은 공식적인 언어와 법적 참조를 사용하여 합법적으로 보이게 하여 수신자가 랜섬웨어가 포함된 악성 첨부파일을 열도록 속입니다.

{{< ad-banner >}}

이 캠페인은 국제 법 집행 기관에 대한 신뢰를 악용하여 피해자의 방어를 낮춥니다. 첨부파일이 열리면 랜섬웨어가 파일을 암호화하고 지불을 요구합니다. 보고서에는 특정 CVE 또는 CVSS 점수가 언급되지 않았습니다.

조직은 사용자에게 당국으로부터 온 예상치 못한 이메일을 확인하고, 확인되지 않은 출처의 첨부파일을 열지 않으며, 오프라인 백업을 유지하도록 교육해야 합니다. 이메일 필터링 및 다중 인증을 구현하면 위험을 줄일 수 있습니다.

{{< netrunner-insight >}}

SOC 분석가는 인터폴 브랜딩과 법률 언어가 포함된 이메일을 모니터링해야 하며, 이는 위험 신호입니다. DevSecOps 팀은 이메일 게이트웨이가 알 수 없는 발신자의 첨부파일을 차단하고 엔드포인트 탐지가 랜섬웨어 행동을 조기에 포착할 수 있도록 해야 합니다.

{{< /netrunner-insight >}}

---

**[Cybersecurity360에서 전체 기사 읽기 ›](https://www.cybersecurity360.it/news/finti-messaggi-dellinterpol-usati-per-distribuire-ransomware-come-starne-alla-larga/)**
