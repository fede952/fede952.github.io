---
title: "중요한 Zimbra XSS 결함으로 조작된 이메일을 통한 코드 실행 가능"
date: "2026-07-11T08:44:58Z"
original_date: "2026-07-11T06:45:55"
lang: "ko"
translationKey: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
slug: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Zimbra, Classic Web Client의 중요한 저장형 XSS 취약점에 대해 업데이트를 권고합니다. 이 취약점은 특수하게 조작된 이메일을 통해 임의 코드 실행을 허용합니다."
original_url: "https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html"
source: "The Hacker News"
severity: "Critical"
target: "Zimbra Classic Web Client"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Zimbra, Classic Web Client의 중요한 저장형 XSS 취약점에 대해 업데이트를 권고합니다. 이 취약점은 특수하게 조작된 이메일을 통해 임의 코드 실행을 허용합니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="Zimbra Classic Web Client" >}}

Zimbra가 Classic Web Client에서 중요한 보안 취약점을 공개했습니다. 이 취약점은 저장형 교차 사이트 스크립팅(XSS)을 통해 공격자가 임의 코드를 실행할 수 있게 합니다. 이 결함은 특수하게 조작된 이메일이 사용자 세션 내에서 악성 스크립트를 실행하도록 하여, 이메일 클라이언트 및 관련 데이터의 완전한 손상으로 이어질 수 있습니다.

{{< ad-banner >}}

아직 CVE 식별자가 할당되지 않은 이 취약점은 Classic Web Client 구성 요소에 영향을 미칩니다. Zimbra는 모든 고객에게 위험을 완화하기 위해 즉시 사용 가능한 업데이트를 적용할 것을 촉구하고 있습니다. CVSS 점수는 제공되지 않았지만, 이메일 전달을 통해 코드를 실행할 수 있는 능력은 Zimbra에 의존하는 조직에게 높은 우선순위의 문제입니다.

저장형 XSS 취약점인 이 공격은 악성 이메일을 여는 것 외에 사용자 상호작용이 필요하지 않습니다. 이는 특히 이메일 필터링이 조작된 페이로드를 감지하지 못할 수 있는 환경에서 악용 가능성을 높입니다. 관리자는 패치를 우선시하고 이메일 보안 제어를 검토해야 합니다.

{{< netrunner-insight >}}

SOC 분석가에게 이는 전통적인 이메일 필터를 우회하는 전형적인 저장형 XSS입니다. DevSecOps 팀은 즉시 Zimbra Classic Web Client를 패치하고 XSS 규칙이 있는 웹 애플리케이션 방화벽 배포를 고려해야 합니다. 사용자 세션에서 비정상적인 스크립트 실행을 탐지 신호로 모니터링하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html)**
