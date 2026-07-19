---
title: "7개의 악성 npm 패키지, 블록체인 C2로 Vite 생태계 공격"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "ko"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx, ViteVenom 캠페인 발견: 블록체인 기반 C2 인프라를 사용해 7개의 악성 npm 패키지로 Vite 프론트엔드 도구 생태계를 노려 RAT 유포"
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Vite 프론트엔드 도구 생태계"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx, ViteVenom 캠페인 발견: 블록체인 기반 C2 인프라를 사용해 7개의 악성 npm 패키지로 Vite 프론트엔드 도구 생태계를 노려 RAT 유포

{{< cyber-report severity="High" source="The Hacker News" target="Vite 프론트엔드 도구 생태계" >}}

Checkmarx의 사이버보안 연구원들이 Vite 프론트엔드 도구 생태계를 노리는 7개의 악성 npm 패키지 클러스터를 식별했습니다. 이는 소프트웨어 공급망 공격의 일환입니다. ViteVenom으로 명명된 이 캠페인은 이전에 관찰된 ChainVeil 작전의 확장으로, Tron 네트워크에 걸친 전례 없는 4계층 블록체인 기반 명령 및 제어(C2) 인프라를 활용했습니다.

{{< ad-banner >}}

악성 패키지는 손상된 시스템에 원격 접근 트로이 목마(RAT)를 전달하여 공격자가 데이터를 유출하고 지속적인 접근을 유지할 수 있도록 설계되었습니다. C2 통신에 블록체인을 사용하면 인프라가 분산되어 전통적인 싱크홀링 기술에 저항하므로 탐지 및 제거가 더 어려워집니다.

개발 파이프라인에서 Vite를 사용하는 조직은 즉시 식별된 악성 패키지에 대한 종속성을 감사하고 엄격한 패키지 무결성 검사를 구현해야 합니다. 이 사건은 공격자가 합법적인 개발 도구와 분산 네트워크를 활용하여 탐지를 회피하는 소프트웨어 공급망 공격의 정교함이 증가하고 있음을 강조합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우 블록체인 노드로의 아웃바운드 연결과 비정상적인 DNS 쿼리를 모니터링하면 이 C2 기술을 탐지하는 데 도움이 됩니다. DevSecOps 팀은 패키지 서명을 시행하고 종속성 스캐닝 도구를 사용하여 알려진 악성 패키지가 빌드 파이프라인에 진입하기 전에 차단해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
