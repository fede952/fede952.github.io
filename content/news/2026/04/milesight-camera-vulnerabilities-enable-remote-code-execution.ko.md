---
title: "Milesight 카메라 취약점으로 원격 코드 실행 가능"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "ko"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA는 여러 Milesight 카메라 모델이 치명적인 취약점(CVE-2026-28747 등)에 영향을 받아 장치 충돌 또는 원격 코드 실행으로 이어질 수 있다고 경고합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Milesight IP 카메라"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA는 여러 Milesight 카메라 모델이 치명적인 취약점(CVE-2026-28747 등)에 영향을 받아 장치 충돌 또는 원격 코드 실행으로 이어질 수 있다고 경고합니다.

{{< cyber-report severity="Critical" source="CISA" target="Milesight IP 카메라" cve="CVE-2026-28747" >}}

CISA는 광범위한 Milesight 카메라 모델에 영향을 미치는 여러 취약점을 상세히 설명하는 권고(ICSA-26-113-03)를 발표했습니다. CVE-2026-28747, CVE-2026-27785, CVE-2026-32644, CVE-2026-32649, CVE-2026-20766로 식별된 이 결함은 MS-Cxx63-PD, MS-Cxx64-xPD 등 여러 제품 라인의 펌웨어 버전에 영향을 미칩니다. 성공적으로 악용될 경우 공격자가 장치를 충돌시키거나 원격 코드 실행을 달성할 수 있습니다.

{{< ad-banner >}}

영향을 받는 모델은 여러 시리즈에 걸쳐 있으며, 펌웨어 버전은 51.7.0.77-r12, 3x.8.0.3-r11, 63.8.0.4-r3 등입니다. 원격 코드 실행의 심각성을 고려할 때, 이러한 취약점은 감시 또는 IoT 배포에서 Milesight 카메라를 사용하는 조직에 상당한 위험을 초래합니다. CISA는 사용 가능한 패치를 적용하고 공급업체 지침에 따라 노출을 완화할 것을 권장합니다.

권고에는 CVSS 점수나 활발한 악용 증거가 제공되지 않았지만, 장치 손상 및 네트워크 침입 가능성은 즉각적인 주의를 기울여야 합니다. 보안 팀은 영향을 받는 카메라 모델을 인벤토리화하고, IoT 장치를 중요 네트워크에서 분리하며, 펌웨어 업데이트를 우선시해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 카메라 서브넷에서 비정상적인 트래픽을 모니터링하고 이러한 장치가 격리되었는지 확인해야 합니다. DevSecOps 엔지니어는 모든 Milesight 카메라의 패치를 신속히 적용해야 합니다. 에지 장치의 원격 코드 실행 취약점은 종종 측면 이동의 진입점이 되기 때문입니다. 공급업체 패치가 확인될 때까지 이러한 CVE를 중요하게 처리하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
