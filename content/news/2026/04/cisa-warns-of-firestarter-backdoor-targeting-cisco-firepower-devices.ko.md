---
title: "CISA, Cisco Firepower 장치를 표적으로 하는 FIRESTARTER 백도어에 대해 경고"
date: "2026-04-23T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA와 NCSC가 APT 행위자가 Cisco ASA/FTD 장치에 지속성을 유지하기 위해 FIRESTARTER 백도어를 사용하고 있다고 경고합니다. 긴급 대응 조치가 제시되었습니다."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Cisco Firepower 및 Secure Firewall 장치"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA와 NCSC가 APT 행위자가 Cisco ASA/FTD 장치에 지속성을 유지하기 위해 FIRESTARTER 백도어를 사용하고 있다고 경고합니다. 긴급 대응 조치가 제시되었습니다.

{{< cyber-report severity="High" source="CISA" target="Cisco Firepower 및 Secure Firewall 장치" >}}

CISA와 영국 NCSC는 FIRESTARTER 백도어에 대한 악성코드 분석 보고서를 발표했습니다. 이 백도어는 고급 지속 위협(APT) 행위자가 ASA 또는 FTD 소프트웨어를 실행하는 공개적으로 접근 가능한 Cisco Firepower 및 Secure Firewall 장치에 지속성을 유지하기 위해 사용하고 있습니다. 이 분석은 법의학 조사에서 얻은 샘플을 기반으로 하며, CISA는 ASA 소프트웨어를 실행하는 Cisco Firepower 장치에 실제로 성공적인 임플란트가 이루어졌음을 확인했습니다.

{{< ad-banner >}}

이번 발표는 CISA의 긴급 지시 25-03에 따른 것으로, 미국 FCEB 기관에 코어 덤프를 수집하여 CISA의 Malware Next Generation 플랫폼에 제출하고 24/7 운영 센터를 통해 즉시 보고할 것을 촉구합니다. 조직은 CISA가 다음 단계를 제공할 때까지 추가 조치를 취하지 않는 것이 좋습니다.

악성코드는 Cisco Firepower 및 Secure Firewall 장치 모두와 관련이 있지만, CISA는 ASA를 실행하는 Firepower 장치에서만 성공적인 임플란트를 관찰했습니다. 보고서는 경계를 늦추지 않고 침해 지표를 사전에 탐지해야 할 필요성을 강조합니다.

{{< netrunner-insight >}}

SOC 분석가는 Cisco ASA/FTD 장치에서 코어 덤프를 수집하여 CISA에 분석을 제출하는 것을 우선시해야 합니다. DevSecOps 팀은 Cisco 장치가 모범 사례에 따라 패치되고 구성되도록 하고, 비정상적인 지속성 메커니즘을 모니터링해야 합니다. 이 백도어는 APT 수준의 위협으로부터 네트워크 에지 장치를 보호하는 것의 중요성을 강조합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
