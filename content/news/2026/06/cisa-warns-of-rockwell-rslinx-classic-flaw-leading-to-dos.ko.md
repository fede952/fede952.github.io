---
title: "CISA, Rockwell RSLinx Classic 결함으로 인한 DoS 위험 경고"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "ko"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 권고는 Rockwell Automation RSLinx Classic ≤4.50.00의 스택 기반 버퍼 오버플로우인 CVE-2020-13573을 강조하며, 서비스 거부 및 원격 코드 실행 위험이 있습니다."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 권고는 Rockwell Automation RSLinx Classic ≤4.50.00의 스택 기반 버퍼 오버플로우인 CVE-2020-13573을 강조하며, 서비스 거부 및 원격 코드 실행 위험이 있습니다.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA는 널리 사용되는 산업용 통신 소프트웨어인 Rockwell Automation RSLinx Classic의 취약점에 관한 권고(ICSA-26-167-02)를 발표했습니다. CVE-2020-13573으로 식별된 이 결함은 스택 기반 버퍼 오버플로우로, 원격으로 악용되어 임의 코드를 실행하거나 서비스 거부를 유발하여 애플리케이션이 응답하지 않고 자동으로 복구되지 못하게 할 수 있습니다.

{{< ad-banner >}}

영향을 받는 버전은 RSLinx Classic 4.50.00까지 포함됩니다. 이 취약점은 CVSS v3 점수 7.5로 높은 심각도를 나타냅니다. Rockwell Automation은 버전 4.60.00 이상으로 업그레이드하거나 즉시 업그레이드할 수 없는 고객을 위해 패치 BF31213을 적용할 것을 권장합니다. 권고는 또한 기본 약점으로 CWE-125(범위를 벗어난 읽기)를 언급합니다.

관련된 중요 인프라 부문(제조, 에너지, 식품 및 농업, 물 및 폐수)과 제품의 전 세계적 배포를 고려할 때, 시기적절한 패치 적용이 필수적입니다. 조직은 특히 RSLinx Classic이 신뢰할 수 없는 네트워크에 노출된 환경에서 악용 위험을 완화하기 위해 이 업데이트를 우선시해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, RSLinx Classic 프로세스에서 비정상적인 충돌 또는 응답 없음을 모니터링하십시오. 이는 악용 시도를 나타낼 수 있습니다. DevSecOps 팀은 즉시 버전 4.60.00으로의 업그레이드를 계획하거나 패치 BF31213을 적용하고, RSLinx 인스턴스가 인터넷에서 직접 접근 가능하지 않도록 해야 합니다. CVSS 점수와 원격 코드 실행 가능성을 고려하여 이를 높은 우선순위의 수정 항목으로 처리하십시오.

{{< /netrunner-insight >}}

---

**[CISA에서 전체 기사 읽기 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
