---
title: "ABB Zenon 원격 전송 결함으로 인증되지 않은 재부팅 가능"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "ko"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA가 ABB Ability Zenon의 CVE-2025-8754에 대해 경고, 원격 전송 서비스를 통해 무단 시스템 재부팅 가능. 현재까지 활발한 악용 사례는 보고되지 않음."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "ABB Ability Zenon 시스템"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA가 ABB Ability Zenon의 CVE-2025-8754에 대해 경고, 원격 전송 서비스를 통해 무단 시스템 재부팅 가능. 현재까지 활발한 악용 사례는 보고되지 않음.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Zenon 시스템" cve="CVE-2025-8754" cvss="7.5" >}}

CISA는 ABB Ability Zenon의 원격 전송 서비스에서 인증 누락 취약점을 상세히 설명하는 권고(ICSA-26-146-03)를 발표했습니다. CVE-2025-8754로 추적되며 CVSS 점수 7.5인 이 결함은 공격자가 적절한 자격 증명 없이 시스템 재부팅을 유발할 수 있게 합니다. 영향을 받는 버전은 7.50부터 14까지입니다.

{{< ad-banner >}}

악용하려면 사전 네트워크 접근이 필요하며, 공격자는 대상 Zenon 시스템과 동일한 네트워크에 이미 있어야 합니다. ABB는 기본 구성에서 zensyssrv.exe 서비스가 자동으로 시작되지만, 사용자가 원격 전송 서비스를 사용하려면 비밀번호를 구성해야 한다고 밝혔습니다. 현재까지 실제 환경에서 활발한 악용 증거는 없습니다.

이 권고는 ABB Ability Zenon이 화학, 에너지, 의료, 물 및 폐수 시스템 등 전 세계 중요 인프라 부문에 광범위하게 배포되어 있음을 강조합니다. 영향을 받는 버전을 사용하는 조직은 잠재적 서비스 거부 공격을 방지하기 위해 ABB가 제공하는 완화 조치나 업데이트를 즉시 적용해야 합니다.

{{< netrunner-insight >}}

SOC 분석가: Zenon 시스템의 노출을 제한하기 위해 네트워크 분할을 우선시하고, 원격 전송 서비스 비밀번호가 구성되어 있고 강력한지 확인하십시오. DevSecOps 팀은 zensyssrv.exe 서비스가 신뢰할 수 없는 네트워크에 노출되지 않도록 확인하고, 공급업체 패치가 제공되는 즉시 적용해야 합니다. CVSS 7.5 및 중요 인프라 영향을 고려할 때, 활발한 악용이 없더라도 이를 높은 우선순위의 발견으로 처리하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
