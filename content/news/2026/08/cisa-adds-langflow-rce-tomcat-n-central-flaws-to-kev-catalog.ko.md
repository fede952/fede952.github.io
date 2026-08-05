---
title: "CISA, Langflow RCE, Tomcat, N-central 취약점을 KEV 카탈로그에 추가"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "ko"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA는 CVSS 9.8의 Langflow RCE(CVE-2026-9198)를 포함하여 활발히 악용되는 세 가지 취약점을 플래그 지정하고, 즉각적인 패치를 촉구했습니다."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA는 CVSS 9.8의 Langflow RCE(CVE-2026-9198)를 포함하여 활발히 악용되는 세 가지 취약점을 플래그 지정하고, 즉각적인 패치를 촉구했습니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

미국 사이버보안 및 인프라 보안국(CISA)은 활발한 악용 증거를 인용하여 세 가지 취약점을 KEV(알려진 악용 취약점) 카탈로그에 추가했습니다. 그중에는 Langflow의 치명적인 코드 주입 결함인 CVE-2026-9198이 포함되어 있으며, 이는 인증되지 않은 공격자가 완전한 원격 코드 실행을 달성할 수 있게 합니다. 이 취약점은 CVSS 점수 9.8로 심각한 위험을 나타냅니다.

{{< ad-banner >}}

나머지 두 결함은 Apache Tomcat과 N-central에 영향을 미치지만, 요약에는 구체적인 세부 정보가 제공되지 않습니다. CISA의 KEV 카탈로그는 악용이 알려진 취약점의 우선순위 목록이며, 연방 기관은 지정된 기한 내에 이를 해결해야 합니다. 조직은 카탈로그를 검토하고 즉시 패치를 적용할 것을 권고합니다.

이러한 취약점의 포함은 적시에 패치 관리와 위협 인텔리전스의 중요성을 강조합니다. 보안 팀은 이러한 CVE와 관련된 손상 지표를 모니터링하고 자산이 알려진 공격 벡터에 노출되지 않도록 해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, Langflow, Tomcat 및 N-central에 대한 악용 시도를 모니터링하는 데 우선순위를 두십시오. 이제 이들은 확인된 활성 대상입니다. DevSecOps는 특히 인터넷에 노출된 인스턴스에 대한 패치를 신속히 진행하고, 사후 악용 활동에 대한 추가 탐지 규칙 구현을 고려해야 합니다. 치명적인 CVSS 점수를 고려하여 CVE-2026-9198을 최상위 위험으로 취급하고 무단 액세스가 발생하지 않았는지 검증하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
