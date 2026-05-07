---
title: "Mirai 기반 xlabs_v1 봇넷, ADB를 통해 IoT 기기를 하이재킹하여 DDoS 공격 수행"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "ko"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "연구진이 노출된 Android Debug Bridge 포트를 악용하여 IoT 기기를 DDoS 네트워크에 편입시키는 새로운 Mirai 기반 봇넷 xlabs_v1을 발견했습니다."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "ADB가 노출된 IoT 기기"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

연구진이 노출된 Android Debug Bridge 포트를 악용하여 IoT 기기를 DDoS 네트워크에 편입시키는 새로운 Mirai 기반 봇넷 xlabs_v1을 발견했습니다.

{{< cyber-report severity="High" source="The Hacker News" target="ADB가 노출된 IoT 기기" >}}

사이버보안 연구진이 Android Debug Bridge(ADB)를 실행하는 인터넷 노출 기기를 대상으로 하는 새로운 Mirai 기반 봇넷, 자칭 xlabs_v1을 식별했습니다. 이 봇넷은 감염된 기기를 분산 서비스 거부(DDoS) 공격을 시작할 수 있는 네트워크로 편입시키는 것을 목표로 합니다.

{{< ad-banner >}}

이 발견은 Hunt.io가 네덜란드에 호스팅된 서버의 노출된 디렉토리를 식별한 후 이루어졌습니다. 이 악성코드는 Android 기기 디버깅에 사용되는 명령줄 도구인 ADB를 악용하며, 이는 종종 IoT 기기에서 노출된 상태로 남아 있어 원격 공격자가 무단 액세스할 수 있게 합니다.

이 캠페인은 취약하게 보호된 IoT 기기를 대상으로 하는 Mirai 변종의 지속적인 위협을 강조합니다. 조직은 프로덕션 기기에서 ADB를 비활성화하고 네트워크 액세스를 제한하여 이러한 하이재킹을 방지할 것을 권고합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우 외부 IP에서의 예상치 못한 ADB 연결을 모니터링하십시오. DevSecOps 팀은 프로덕션 빌드에서 ADB가 비활성화되고 IoT 기기가 중요 네트워크와 분리되어 이 봇넷의 영향력을 완화하도록 해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
