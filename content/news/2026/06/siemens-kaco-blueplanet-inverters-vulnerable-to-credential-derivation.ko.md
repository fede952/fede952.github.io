---
title: "지멘스 KACO Blueplanet 인버터, 자격 증명 유출 취약점 발견"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "ko"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "KACO blueplanet 인버터의 다중 취약점으로 인해 공격자가 일련번호에서 자격 증명을 유추하여 무단 액세스 권한을 얻을 수 있습니다. 지멘스는 업데이트를 권장합니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "지멘스 KACO Blueplanet 인버터"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

KACO blueplanet 인버터의 다중 취약점으로 인해 공격자가 일련번호에서 자격 증명을 유추하여 무단 액세스 권한을 얻을 수 있습니다. 지멘스는 업데이트를 권장합니다.

{{< cyber-report severity="High" source="CISA" target="지멘스 KACO Blueplanet 인버터" >}}

CISA가 지멘스 KACO blueplanet 인버터의 여러 취약점을 상세히 설명하는 권고(ICSA-26-160-02)를 발표했습니다. 이러한 결함으로 인해 공격자가 장치의 일련번호에서 자격 증명을 유추하여 이를 악용해 인버터에 무단 액세스할 수 있습니다.

{{< ad-banner >}}

이 권고는 blueplanet 100 NX3 M8, 100 TL3 GEN2, 105 TL3 등 다양한 모델을 포함하며, 버전은 all/* 또는 6.1.4.9 미만의 특정 펌웨어 버전으로 명시되어 있습니다. KACO new energy GmbH는 일부 제품에 대한 업데이트를 출시했으며, 다른 제품에 대한 수정을 준비 중이며, 패치가 아직 제공되지 않은 경우 대응 조치를 권장합니다.

권고에는 CVE 식별자나 CVSS 점수가 제공되지 않습니다. 이러한 취약점은 원격 악용을 통해 무단 장치 액세스로 이어질 수 있어 태양광 에너지 인프라에 영향을 미칠 수 있으므로 심각한 것으로 간주됩니다.

{{< netrunner-insight >}}

SOC 분석가와 DevSecOps 엔지니어에게 이 권고는 IoT/OT 장치에서 하드코딩되거나 유추 가능한 자격 증명의 위험을 강조합니다. 영향을 받는 KACO 인버터를 즉시 인벤토리화하고 가능한 경우 펌웨어 업데이트를 적용하십시오. 패치되지 않은 장치의 경우 네트워크 분할을 구현하고 임시 완화 조치로 비정상적인 액세스 시도를 모니터링하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
