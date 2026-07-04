---
title: "FBI, NetNut 프록시 서비스 및 Popa 봇넷 인프라 압수"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "ko"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI가 조사 보도에 따라 200만 대의 감염된 장치로 구성된 Popa 봇넷과 연계된 가정용 프록시 서비스 NetNut 관련 도메인을 압수했습니다."
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "가정용 프록시 서비스 NetNut 및 Popa 봇넷"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI가 조사 보도에 따라 200만 대의 감염된 장치로 구성된 Popa 봇넷과 연계된 가정용 프록시 서비스 NetNut 관련 도메인을 압수했습니다.

{{< cyber-report severity="High" source="Krebs on Security" target="가정용 프록시 서비스 NetNut 및 Popa 봇넷" >}}

FBI는 업계 파트너와 협력하여 이스라엘 상장 기업 Alarum Technologies(NASDAQ: ALAR)가 운영하는 가정용 프록시 서비스 NetNut와 관련된 수백 개의 도메인을 압수했습니다. 이 조치는 KrebsOnSecurity의 보도에 따른 것으로, 해당 보도는 NetNut를 사용자 동의 없이 감염된 최소 200만 대의 장치로 구성된 Popa 봇넷과 연결했습니다.

{{< ad-banner >}}

Popa 봇넷은 감염된 장치를 활용하여 NetNut의 프록시 인프라를 통해 트래픽을 라우팅함으로써 자격 증명 스터핑, 광고 사기, 계정 탈취 등 악성 활동을 가능하게 합니다. 이번 압수는 프록시 서비스와 봇넷의 명령 및 제어 기능을 모두 마비시킵니다.

이번 작전은 사이버 범죄를 용이하게 하는 프록시 서비스를 대상으로 한 법 집행 기관의 증가 추세를 강조합니다. 조직은 압수된 도메인에 대한 연결을 위해 네트워크 트래픽을 검토하고 잔여 봇넷 활동을 모니터링해야 합니다.

{{< netrunner-insight >}}

SOC 분석가에게 이번 압수는 위협 인텔리전스 피드에서 가정용 프록시 IP 범위를 모니터링하는 중요성을 강조합니다. DevSecOps 팀은 타사 프록시 서비스와의 모든 통합을 감사하고, Popa의 잔재가 대체 인프라에 남아 있을 수 있으므로 강력한 봇넷 탐지 메커니즘을 갖추어야 합니다.

{{< /netrunner-insight >}}

---

**[Krebs on Security에서 전체 기사 읽기 ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
