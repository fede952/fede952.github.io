---
title: "ABB B&R PC, 다중 CVE에 피격: RCE, DoS, DNS 중독"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "ko"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 ABB B&R 산업용 PC의 취약점에 대해 경고합니다. 업데이트가 제공됩니다. 공격자는 원격 코드 실행, DoS, DNS 캐시 중독 또는 데이터 도난을 달성할 수 있습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "ABB B&R 산업용 PC"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 ABB B&R 산업용 PC의 취약점에 대해 경고합니다. 업데이트가 제공됩니다. 공격자는 원격 코드 실행, DoS, DNS 캐시 중독 또는 데이터 도난을 달성할 수 있습니다.

{{< cyber-report severity="High" source="CISA" target="ABB B&R 산업용 PC" cve="CVE-2023-45229" >}}

ABB는 APC4100, APC910, C80, MPC3100, PPC1200, PPC900 및 APC2200을 포함한 여러 B&R 산업용 PC 제품 라인에 영향을 미치는 취약점을 공개했습니다. CVE-2023-45229부터 CVE-2023-45237까지 추적되는 이 결함은 네트워크 기반 공격자가 원격 코드를 실행하고, 서비스 거부 공격을 시작하고, DNS 캐시를 중독시키거나, 민감한 정보를 추출할 수 있도록 합니다.

{{< ad-banner >}}

권고문은 각 제품에 대해 영향을 받는 버전을 나열하며, 문제를 해결하기 위한 업데이트가 제공됩니다. 예를 들어, APC4100 버전 1.09 미만은 취약하며, 버전 1.09는 패치되었습니다. 마찬가지로, APC910 버전 1.25 이하는 영향을 받습니다. ABB는 즉시 최신 펌웨어 버전으로 업그레이드할 것을 권장합니다.

산업 제어 시스템(ICS) 맥락을 고려할 때, 이러한 취약점은 운영 기술 환경에 상당한 위험을 초래합니다. 영향을 받는 ABB B&R PC를 사용하는 조직은 특히 장치가 신뢰할 수 없는 네트워크에 노출된 경우 패치 적용을 우선시해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, B&R PC에서 비정상적인 DNS 쿼리나 예상치 못한 연결이 있는지 네트워크 트래픽을 모니터링하십시오. DevSecOps 팀은 영향을 받는 모든 장치를 인벤토리화하고 가능한 한 빨리 펌웨어 업데이트를 적용해야 합니다. 이러한 CVE는 인증 없이 원격 코드 실행을 가능하게 하기 때문입니다. ICS 네트워크를 세분화하여 노출을 제한하는 것을 고려하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
