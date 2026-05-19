---
title: "Ivanti, Fortinet, SAP, VMware, n8n, RCE, SQLi, 권한 상승 취약점 패치"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "ko"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "여러 벤더가 Ivanti Xtraction CVE-2026-8043(CVSS 9.6)을 포함한 중요 취약점에 대한 보안 수정 사항을 발표했습니다. 이 취약점은 정보 노출 또는 클라이언트 측 공격으로 이어질 수 있습니다."
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

여러 벤더가 Ivanti Xtraction CVE-2026-8043(CVSS 9.6)을 포함한 중요 취약점에 대한 보안 수정 사항을 발표했습니다. 이 취약점은 정보 노출 또는 클라이언트 측 공격으로 이어질 수 있습니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP, VMware가 인증 우회 및 임의 코드 실행에 악용될 수 있는 여러 취약점을 해결하는 보안 패치를 발표했습니다. 가장 심각한 결함은 Ivanti Xtraction의 CVE-2026-8043로, CVSS 점수 9.6이며 파일 이름 외부 제어로 인해 정보 노출 또는 클라이언트 측 공격이 가능합니다.

{{< ad-banner >}}

다른 벤더들도 SQL 삽입 및 권한 상승 취약점을 포함한 높은 심각도의 문제를 해결했습니다. 조직은 특히 인터넷에 노출된 시스템의 경우 이러한 결함을 우선적으로 패치해야 하며, 전체 시스템 손상으로 이어질 수 있습니다.

아직 활발한 악용 사례는 보고되지 않았지만, 광범위한 공격 표면과 높은 CVSS 점수로 인해 보안 팀의 즉각적인 주의가 필요합니다. 정기적인 취약점 스캔 및 패치 관리는 위험을 완화하는 데 중요합니다.

{{< netrunner-insight >}}

SOC 분석가는 Ivanti Xtraction CVE-2026-8043 패치를 우선시해야 합니다. 이는 중요한 CVSS 점수와 클라이언트 측 공격 가능성 때문입니다. DevSecOps 팀은 영향을 받는 모든 시스템이 업데이트되었는지 확인하고 파일 이름 외부 제어가 데이터 유출 또는 측면 이동으로 이어질 수 있으므로 악용 징후를 모니터링해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
