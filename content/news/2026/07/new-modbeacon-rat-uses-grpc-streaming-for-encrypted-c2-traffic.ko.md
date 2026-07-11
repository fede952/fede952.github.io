---
title: "새로운 MODBEACON RAT, 암호화된 C2 트래픽에 gRPC 스트리밍 사용"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "ko"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "중국 연계 실버 폭스 그룹이 SEO 중독을 통해 Rust 기반 MODBEACON RAT를 배포하며, 암호화된 C2 통신에 gRPC 스트리밍을 사용합니다."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "가짜 설치 프로그램을 통한 Windows 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

중국 연계 실버 폭스 그룹이 SEO 중독을 통해 Rust 기반 MODBEACON RAT를 배포하며, 암호화된 C2 통신에 gRPC 스트리밍을 사용합니다.

{{< cyber-report severity="High" source="The Hacker News" target="가짜 설치 프로그램을 통한 Windows 사용자" >}}

중국 연계 사이버 범죄 그룹 실버 폭스가 MODBEACON이라는 새로운 Rust 기반 원격 접근 트로이목마(RAT)와 관련된 것으로 밝혀졌습니다. 이 악성코드는 암호화된 명령 및 제어(C2) 트래픽에 gRPC 스트리밍을 사용하여 탐지를 더 어렵게 만듭니다.

{{< ad-banner >}}

중국 사이버 보안 회사 치안신(QiAnXin)에 따르면, 실버 폭스는 SEO 중독 기술을 사용하여 가짜 설치 프로그램을 통해 MODBEACON을 유포합니다. 이 그룹은 낮은 정교함과 높은 활동성을 가진 운영처럼 보일 수 있지만, 실제 조직적 역량은 더 고도화되어 있습니다.

C2 통신에 gRPC 스트리밍을 사용하는 것은 악성코드에 새로운 기술로, HTTP/2와 프로토콜 버퍼를 활용하여 정상 트래픽에 섞여 들어갑니다. 보안 팀은 비정상적인 gRPC 트래픽을 모니터링하고 SEO 중독된 다운로드 사이트를 조사해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 탐지 파이프라인에 gRPC 트래픽 분석을 추가해야 합니다. MODBEACON의 스트리밍 RPC 사용은 전통적인 네트워크 시그니처를 회피할 수 있기 때문입니다. DevSecOps 팀은 소프트웨어 다운로드의 무결성을 확인하고 알려진 SEO 중독 도메인을 차단하는 것을 고려해야 합니다. 이 RAT는 Rust 기반 악성코드에 대한 사전 위협 헌팅의 필요성을 강조합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
