---
title: "CISA, Siemens RUGGEDCOM APE1808의 PAN-OS를 통한 치명적 버퍼 오버플로 경고"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Palo Alto Networks PAN-OS Captive Portal의 버퍼 오버플로가 Siemens RUGGEDCOM APE1808 장치에 영향을 미칩니다. CVE-2026-0300은 인증되지 않은 원격 코드 실행을 루트 권한으로 허용합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Siemens RUGGEDCOM APE1808 장치"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Palo Alto Networks PAN-OS Captive Portal의 버퍼 오버플로가 Siemens RUGGEDCOM APE1808 장치에 영향을 미칩니다. CVE-2026-0300은 인증되지 않은 원격 코드 실행을 루트 권한으로 허용합니다.

{{< cyber-report severity="Critical" source="CISA" target="Siemens RUGGEDCOM APE1808 장치" cve="CVE-2026-0300" cvss="10.0" >}}

CISA는 Palo Alto Networks PAN-OS 소프트웨어의 User-ID Authentication Portal(Captive Portal) 서비스에서 치명적인 버퍼 오버플로 취약점을 설명하는 권고(ICSA-26-139-02)를 발표했습니다. CVSS 점수 10.0으로 추적되는 이 결함(CVE-2026-0300)은 인증되지 않은 공격자가 특수 제작된 패킷을 전송하여 PA-Series 및 VM-Series 방화벽에서 루트 권한으로 임의 코드를 실행할 수 있게 합니다.

{{< ad-banner >}}

이 취약점은 모든 버전의 Siemens RUGGEDCOM APE1808 장치에 영향을 미칩니다. Siemens는 수정 버전을 준비 중이며 Palo Alto Networks의 상위 보안 알림에 제공된 해결 방법을 구현할 것을 권장합니다. 패치가 제공될 때까지 조직은 Captive Portal 서비스가 필요하지 않은 경우 비활성화하고 영향을 받는 장치에 대한 네트워크 액세스를 제한해야 합니다.

CVSS 점수가 치명적이고 전체 시스템 손상 가능성을 고려할 때 즉각적인 조치가 필요합니다. 이 권고는 전 세계에 배포된 장치를 대상으로 Critical Manufacturing 부문을 대상으로 합니다. 운영자는 완화 조치를 우선 적용하고 악용 징후를 모니터링해야 합니다.

{{< netrunner-insight >}}

이것은 공급망 위험의 전형적인 예입니다: 타사 구성 요소(PAN-OS)가 산업 제품에 치명적인 결함을 도입합니다. SOC 분석가는 즉시 Captive Portal 포트로의 비정상 트래픽을 탐지하고 세분화가 노출을 제한하는지 확인해야 합니다. DevSecOps 팀은 RUGGEDCOM APE1808의 모든 인스턴스를 인벤토리화하고 지체 없이 상위 Palo Alto Networks 완화 조치를 적용해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
