---
title: "GigaWiper 백도어, 디스크 삭제, 가짜 랜섬웨어 및 스파이웨어 결합"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "ko"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft가 GigaWiper를 발견했습니다. 이 모듈식 Windows 백도어는 디스크 삭제 도구, 가짜 랜섬웨어, 스파이웨어 등 세 가지 파괴적 도구를 포함하여 엔드포인트에 심각한 위협을 가합니다."
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Windows 엔드포인트"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft가 GigaWiper를 발견했습니다. 이 모듈식 Windows 백도어는 디스크 삭제 도구, 가짜 랜섬웨어, 스파이웨어 등 세 가지 파괴적 도구를 포함하여 엔드포인트에 심각한 위협을 가합니다.

{{< cyber-report severity="High" source="The Hacker News" target="Windows 엔드포인트" >}}

Microsoft는 GigaWiper라는 새로운 파괴적 Windows 백도어를 식별했습니다. 이 백도어는 세 가지 오래된 악성 프로그램을 단일 모듈식 프레임워크에 통합합니다. 이 백도어는 운영자에게 선택할 수 있는 명령 메뉴를 제공하며, 각 명령은 전체 디스크 삭제, Windows 시스템 드라이브 덮어쓰기, 또는 키가 저장되지 않는 가짜 랜섬웨어 실행 등 다양한 유형의 피해를 입히도록 설계되었습니다.

{{< ad-banner >}}

GigaWiper의 모듈식 설계는 공격자가 대상 환경에 따라 파괴적 행동을 맞춤화할 수 있게 합니다. 디스크 삭제 기능과 가짜 랜섬웨어의 포함은 주요 목표가 금전적 이득보다는 최대한의 혼란과 데이터 손실을 일으키는 것임을 시사합니다. 이러한 기술 조합은 GigaWiper를 파괴적 사이버 작전을 위한 다재다능하고 위험한 도구로 만듭니다.

구체적인 유포 경로는 공개되지 않았지만, 백도어가 전체 디스크를 삭제하고 랜섬웨어 공격을 시뮬레이션할 수 있는 능력은 높은 수준의 정교함을 나타냅니다. 조직은 엔드포인트 탐지 및 대응(EDR) 솔루션을 우선시하고 강력한 백업 전략을 보장하여 이러한 위협의 영향을 완화해야 합니다.

{{< netrunner-insight >}}

SOC 분석가에게 GigaWiper는 대량 파일 작업 및 디스크 수준 쓰기를 플래그하는 행동 탐지 규칙의 필요성을 강조합니다. DevSecOps 팀은 백업 무결성을 검증하고 복구 절차를 정기적으로 테스트해야 합니다. 가짜 랜섬웨어는 전통적인 복호화 접근 방식을 우회할 수 있기 때문입니다. 검증되지 않은 랜섬웨어 사고는 반대 증거가 나올 때까지 잠재적 와이퍼 공격으로 취급하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
