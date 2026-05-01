---
title: "CISA, ABB PCM600 경로 탐색 취약점으로 인한 RCE 가능성 경고"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB PCM600 버전 1.5~2.13에서 경로 탐색 취약점(CVE-2018-1002208)이 발견되어 임의 코드 실행이 가능합니다. 버전 2.14로 업데이트하십시오."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB PCM600 버전 1.5~2.13에서 경로 탐색 취약점(CVE-2018-1002208)이 발견되어 임의 코드 실행이 가능합니다. 버전 2.14로 업데이트하십시오.

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISA는 보호 및 제어 IED 관리자인 ABB PCM600의 취약점에 대한 권고(ICSA-26-120-02)를 발표했습니다. CVE-2018-1002208로 식별된 이 결함은 SharpZip.dll 라이브러리에 존재하며, 제한된 디렉터리에 대한 경로명의 부적절한 제한(경로 탐색)과 관련됩니다. 성공적으로 악용될 경우 공격자가 시스템 노드에 특수 제작된 메시지를 전송하여 임의 코드 실행을 유발할 수 있습니다.

{{< ad-banner >}}

영향을 받는 제품 버전은 PCM600 1.5부터 2.13까지입니다. ABB는 이 문제를 해결하기 위해 버전 2.14를 출시했습니다. 단, RE_630 보호 계전기는 PCM600 2.14와 호환되지 않으므로, RE_630을 사용하는 이전 버전 사용자는 ABB의 일반 보안 권장 사항에 설명된 대로 시스템 수준 방어에 의존해야 합니다.

권고에 따르면 이 제품은 전 세계 중요 제조 분야에 배포되어 있습니다. 권고에는 CVSS 점수가 제공되지 않았지만, 코드 실행 가능성으로 인해 가능한 한 신속한 패치 적용이 필요합니다. 조직은 PCM600 2.14로의 업데이트를 우선시하고, 즉시 업데이트할 수 없는 시스템에 대해서는 네트워크 분할 및 접근 제어를 구현해야 합니다.

{{< netrunner-insight >}}

ABB PCM600의 이 경로 탐색 취약점은 SharpZip.dll과 같은 레거시 종속성이 위험을 초래할 수 있음을 상기시킵니다. SOC 분석가는 PCM600 노드로의 비정상적인 네트워크 트래픽, 특히 악용 시도를 나타낼 수 있는 조작된 메시지를 모니터링해야 합니다. DevSecOps 엔지니어는 모든 PCM600 인스턴스를 인벤토리화하고 버전 2.14로의 업그레이드를 계획하되, RE_630 계전기와의 호환성 문제는 보완 통제를 통해 해결해야 합니다.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
