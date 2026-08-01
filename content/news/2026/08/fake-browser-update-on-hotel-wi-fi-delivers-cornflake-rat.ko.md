---
title: "호텔 Wi-Fi에서 유포되는 가짜 브라우저 업데이트, CornFlake RAT 유포"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "ko"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft는 하이재킹된 호텔 Wi-Fi를 이용해 가짜 업데이트를 푸시하고 CornFlake 감시 멀웨어를 유포하는 CaptiveCrunch 작전에 대해 경고합니다."
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "호텔 Wi-Fi 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft는 하이재킹된 호텔 Wi-Fi를 이용해 가짜 업데이트를 푸시하고 CornFlake 감시 멀웨어를 유포하는 CaptiveCrunch 작전에 대해 경고합니다.

{{< cyber-report severity="High" source="The Hacker News" target="호텔 Wi-Fi 사용자" >}}

Microsoft는 CaptiveCrunch로 추적되는 새로운 캠페인을 공개했습니다. 이 캠페인은 하이재킹된 호텔 Wi-Fi 네트워크를 이용해 가짜 브라우저 업데이트를 제공합니다. 이러한 업데이트는 실제로는 CornFlake라는 원격 액세스 트로이 목마(RAT)로, 웹캠 이미지, 마이크 오디오, 키 입력을 캡처할 수 있어 감염된 장치를 사실상 감시 도구로 전환합니다.

{{< ad-banner >}}

이 작전은 Storm-2945의 소행으로, Microsoft는 이 그룹을 잘 알려진 위협 그룹 Midnight Blizzard의 운영 하위 클러스터로 평가합니다. 이는 공격 체인이 호텔의 네트워크 인프라를 손상시켜 사용자 트래픽을 가로채고 악성 업데이트 페이지로 리디렉션하는 것을 포함하므로 높은 수준의 정교함과 자원을 시사합니다.

보고서는 특정 CVE 또는 CVSS 점수를 명시하지 않지만, 공격 벡터는 신뢰할 수 있는 환경(호텔 Wi-Fi)을 사용하여 멀웨어를 전달한다는 점에서 주목할 만합니다. 여행자와 비즈니스 전문가는 공공 Wi-Fi에 의존하는 경우가 많고 브라우저 업데이트 프롬프트를 의심 없이 수락할 가능성이 높기 때문에 특히 위험에 노출되어 있습니다.

{{< netrunner-insight >}}

이 캠페인은 신뢰할 수 없는 네트워크에서 발생하는 모든 브라우저 업데이트 프롬프트를 의심해야 한다는 중요성을 강조합니다. SOC 분석가는 최근 호텔 또는 공공 Wi-Fi에 연결된 엔드포인트에서 발생하는 비정상적인 외부 연결을 모니터링하고, 조직의 허용 목록에 없는 업데이트 관련 도메인을 차단하거나 플래그를 지정하는 것을 고려해야 합니다. DevSecOps의 경우 엄격한 업데이트 정책을 시행하고 원격 근무자를 위해 엔터프라이즈급 VPN을 사용하면 이러한 워터링홀 스타일 공격의 위험을 완화할 수 있습니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
