---
title: "AryStinger 봇넷, 4,000개 이상의 D-Link 라우터를 하이재킹하여 프록시 트래픽에 활용"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "ko"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "AryStinger라는 새로운 봇넷이 4,000개 이상의 구형 D-Link 라우터를 감염시켜 악성 트래픽의 프록시로 전환했습니다. CVE 또는 CVSS 데이터는 제공되지 않았습니다."
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "구형 D-Link 라우터"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

AryStinger라는 새로운 봇넷이 4,000개 이상의 구형 D-Link 라우터를 감염시켜 악성 트래픽의 프록시로 전환했습니다. CVE 또는 CVSS 데이터는 제공되지 않았습니다.

{{< cyber-report severity="Medium" source="BleepingComputer" target="구형 D-Link 라우터" >}}

BleepingComputer의 보고서에 따르면, 이전에 문서화되지 않은 AryStinger라는 악성 봇넷이 전 세계적으로 4,000개 이상의 구형 D-Link 라우터를 감염시켰습니다. 이 봇넷은 해당 장치를 악성 트래픽의 프록시로 전환하여 공격자가 활동을 익명화하고 추가 공격을 시작할 수 있도록 합니다.

{{< ad-banner >}}

감염된 라우터는 알려진 취약점이 있는 오래된 펌웨어를 실행 중인 것으로 추정되지만, 보고서에는 특정 CVE 식별자가 공개되지 않았습니다. 봇넷의 인프라와 전파 방법은 여전히 분석 중이지만, 감염 규모는 패치되지 않은 IoT 장치가 초래하는 위험을 강조합니다.

조직은 네트워크 장치를 인벤토리화하고, 펌웨어를 최신 상태로 유지하며, 프록시 사용을 나타낼 수 있는 비정상적인 트래픽 패턴을 모니터링하는 것이 좋습니다. 초기 보고서에 세부 기술 지표가 부족하다는 점은 탐지 시그니처 개발을 위해 추가 조사가 필요함을 시사합니다.

{{< netrunner-insight >}}

SOC 분석가에게 이는 네트워크 장치, 특히 오래된 라우터에서 예상치 못한 아웃바운드 연결을 모니터링해야 한다는 상기시킴입니다. DevSecOps 팀은 펌웨어 업데이트 정책을 시행하고 IoT 장치를 중요 네트워크에서 분리하는 것을 고려해야 합니다. 특정 IoC가 없으므로, 기준 트래픽 분석과 장치 핑거프린팅이 이러한 봇넷 활동을 발견하는 핵심입니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
