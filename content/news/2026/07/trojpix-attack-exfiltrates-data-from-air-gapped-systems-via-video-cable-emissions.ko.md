---
title: "TrojPix 공격, 비디오 케이블 전자파를 이용해 에어갭 시스템에서 데이터 유출"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "ko"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "연구원들이 TrojPix라는 기술을 시연했습니다. 이 기술은 화면 픽셀을 변조하여 비디오 케이블에서 미약한 무선 신호를 방출함으로써 에어갭 컴퓨터에서 데이터를 유출하며, 사전에 악성코드에 감염되어 있어야 합니다."
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "에어갭 시스템"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

연구원들이 TrojPix라는 기술을 시연했습니다. 이 기술은 화면 픽셀을 변조하여 비디오 케이블에서 미약한 무선 신호를 방출함으로써 에어갭 컴퓨터에서 데이터를 유출하며, 사전에 악성코드에 감염되어 있어야 합니다.

{{< cyber-report severity="Medium" source="The Hacker News" target="에어갭 시스템" >}}

산동대학교 연구원들이 TrojPix라는 새로운 공격을 공개했습니다. 이 공격은 비디오 케이블의 전자기 방출을 악용하여 에어갭 컴퓨터에서 데이터를 유출합니다. 이 기술은 사람의 눈에 보이지 않을 정도로 화면 픽셀을 미묘하게 변경하여 비디오 케이블이 미약한 무선 신호를 방출하도록 하며, 이를 근처의 수신기가 포착하고 디코딩할 수 있습니다.

{{< ad-banner >}}

TrojPix는 대상 시스템에 사전에 악성코드를 설치하여 픽셀 값을 조작해야 합니다. 이 접근 방식은 이전의 에어갭 은닉 채널에 비해 현저히 높은 데이터 전송 속도를 달성하므로, 고도로 보안된 환경에서 실질적인 위협이 됩니다. 이 공격은 물리적으로 격리된 네트워크에서도 데이터를 보호하는 것이 여전히 어려운 과제임을 강조합니다.

이 기술은 정교하지만, 사전에 존재하는 악성코드에 의존하기 때문에 적용 가능성이 제한됩니다. 조직은 강력한 엔드포인트 보안을 통해 초기 침해를 방지하고, 민감한 영역에서 비정상적인 전자기 방출을 모니터링하는 데 중점을 두어야 합니다.

{{< netrunner-insight >}}

SOC 분석가에게 TrojPix는 에어갭 시스템도 데이터 유출로부터 안전하지 않다는 점을 강조합니다. 민감한 워크스테이션 근처에서 비정상적인 전자기 신호를 모니터링하고 엄격한 물리적 보안을 시행하십시오. DevSecOps 팀은 비디오 케이블을 차폐하고 가능한 경우 픽셀 수준의 이상 탐지를 구현하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
