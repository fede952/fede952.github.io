---
title: "MiniPlasma Windows 0-Day, 완전 패치된 시스템에서 SYSTEM 권한 상승 가능"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "ko"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "보안 연구원 Chaotic Eclipse가 MiniPlasma에 대한 PoC를 공개했습니다. 이는 Windows Cloud Files Mini Filter Driver(cldflt.sys)의 제로데이로, 완전 패치된 시스템에서 SYSTEM 권한을 부여합니다."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files Mini Filter Driver (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

보안 연구원 Chaotic Eclipse가 MiniPlasma에 대한 PoC를 공개했습니다. 이는 Windows Cloud Files Mini Filter Driver(cldflt.sys)의 제로데이로, 완전 패치된 시스템에서 SYSTEM 권한을 부여합니다.

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files Mini Filter Driver (cldflt.sys)" >}}

최근 공개된 Windows 결함 YellowKey 및 GreenPlasma의 배후에 있는 보안 연구원 Chaotic Eclipse가 완전 패치된 Windows 시스템에서 공격자에게 SYSTEM 권한을 부여하는 Windows 권한 상승 제로데이 결함에 대한 개념 증명(PoC)을 공개했습니다. MiniPlasma라는 코드명의 이 취약점은 Windows Cloud Files Mini Filter Driver인 "cldflt.sys"에 영향을 미칩니다.

{{< ad-banner >}}

이 결함은 제한된 사용자 액세스 권한을 가진 공격자가 권한을 SYSTEM으로 상승시켜 잠재적으로 전체 시스템을 손상시킬 수 있게 합니다. 제로데이로서 현재 공식 패치가 없으므로, PoC가 무기화될 경우 완전 패치된 시스템이 악용에 취약해집니다.

조직은 cldflt.sys 드라이버의 비정상적인 동작을 모니터링하고 Cloud Files 기능에 대한 액세스를 제한하거나 패치가 출시될 때까지 임시 완화 조치를 적용하는 등 추가 강화 조치를 고려해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 cldflt.sys를 대상으로 한 악용 시도를 모니터링하는 데 우선순위를 두어야 합니다. PoC가 공격자의 진입 장벽을 낮추기 때문입니다. DevSecOps 팀은 Windows 이미지 강화를 검토하고, 필요하지 않은 경우 Cloud Files Mini Filter Driver를 비활성화하는 것을 고려하며 Microsoft의 공식 수정을 기다려야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
