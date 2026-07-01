---
title: "RustDuck 봇넷, 라우터와 카메라를 하이재킹하여 DDoS 공격에 활용"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "ko"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "RustDuck이라는 새로운 2단계 멀웨어 패밀리가 2026년 2월부터 추적되며, 가정용 라우터, IP 카메라, 안드로이드 박스, 보안이 취약한 서버를 하이재킹하여 DDoS 네트워크를 구축하고 있습니다."
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "라우터, IP 카메라, 안드로이드 박스, 서버"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

RustDuck이라는 새로운 2단계 멀웨어 패밀리가 2026년 2월부터 추적되며, 가정용 라우터, IP 카메라, 안드로이드 박스, 보안이 취약한 서버를 하이재킹하여 DDoS 네트워크를 구축하고 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="라우터, IP 카메라, 안드로이드 박스, 서버" >}}

QiAnXin의 XLab 연구원들은 2026년 2월부터 RustDuck이라는 새로운 2단계 멀웨어 패밀리를 추적해 왔습니다. 이 봇넷은 가정용 라우터, IP 카메라, 안드로이드 박스, 보안이 취약한 서버를 하이재킹하여 DDoS 공격을 통해 웹사이트와 온라인 서비스를 마비시키는 네트워크로 연결합니다.

{{< ad-banner >}}

이 멀웨어는 메모리 안전 언어인 Rust로 재구축되어 분석과 리버스 엔지니어링을 어렵게 만든다는 점에서 주목할 만합니다. 현재 봇넷의 규모는 크지 않지만, 빠른 진화와 적응력으로 인해 인터넷 인프라에 대한 위협이 증가하고 있습니다.

RustDuck은 Rust의 성능과 안전 기능을 활용하여 더 탄력적이고 탐지하기 어려운 멀웨어를 생성하는 봇넷 개발의 변화를 나타냅니다. 최종 목표는 주요 대상을 마비시킬 수 있는 강력한 DDoS 네트워크를 구축하는 것입니다.

{{< netrunner-insight >}}

SOC 분석가를 위한 조언: IoT 장치와 라우터에서 비정상적인 아웃바운드 트래픽을 모니터링하세요. RustDuck의 2단계 감염은 기존 시그니처를 우회할 수 있습니다. DevSecOps 팀은 엄격한 네트워크 분할을 시행하고 노출된 장치에서 불필요한 서비스를 비활성화하여 공격 표면을 줄여야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
