---
title: "CISA, 활발한 웹 셸 공격 속 PTC Windchill RCE 결함을 KEV에 추가"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "ko"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 PTC Windchill PDMlink 및 FlexPLM의 중요 원격 코드 실행 취약점을 활발한 악용으로 인해 알려진 악용 취약점 카탈로그에 추가했습니다."
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink 및 FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 PTC Windchill PDMlink 및 FlexPLM의 중요 원격 코드 실행 취약점을 활발한 악용으로 인해 알려진 악용 취약점 카탈로그에 추가했습니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink 및 FlexPLM" kev="true" >}}

미국 사이버보안 및 인프라 보안국(CISA)이 PTC Windchill PDMlink 및 PTC FlexPLM에 영향을 미치는 중요 원격 코드 실행 취약점을 알려진 악용 취약점(KEV) 카탈로그에 추가했습니다. 이 결정은 활발한 악용 증거에 따른 것으로, 보고서에 따르면 이러한 엔터프라이즈 제품 데이터 관리(PDM) 및 제품 수명 주기 관리(PLM) 시스템을 대상으로 지속적인 웹 셸 공격이 발생하고 있습니다.

{{< ad-banner >}}

발표에서 특정 CVE 식별자는 공개되지 않았지만, 이 취약점은 영향을 받는 시스템에서 공격자가 임의 코드를 실행할 수 있게 하는 중요 RCE 결함으로 설명됩니다. 이러한 제품을 사용하는 조직은 패치 적용을 우선시하고 환경에서 침해 징후를 검토할 것을 권고하며, 악용 시 전체 시스템 장악으로 이어질 수 있습니다.

CISA의 KEV 카탈로그는 연방 기관에 대한 구속력 있는 운영 지침 역할을 하며, 지정된 기간 내에 수정을 요구합니다. 민간 부문 조직은 이를 높은 우선순위의 위협으로 간주하고 네트워크 분할 및 비정상적인 웹 셸 활동 모니터링과 같은 완화 조치를 구현하는 것이 좋습니다.

{{< netrunner-insight >}}

SOC 분석가는 노출된 Windchill 서버에서 웹 셸 지표를 사냥하는 데 우선순위를 두십시오. 애플리케이션에 의해 생성된 비정상적인 자식 프로세스나 알 수 없는 IP로의 아웃바운드 연결을 찾으십시오. DevSecOps 팀은 사용 가능한 패치를 즉시 적용하고, 패치가 지연될 경우 가상 패치 또는 WAF 규칙 배포를 고려하십시오. 이는 패치 관리에서 종종 간과되는 PLM 시스템이 랜섬웨어 그룹에게 매력적인 표적이 된다는 점을 상기시킵니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
