---
title: "패치되지 않은 Windows Search URI 결함으로 NTLMv2 해시 유출"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "ko"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "연구원들이 Windows search: URI 핸들러의 패치되지 않은 취약점을 공개했습니다. 이 취약점은 CVE-2026-33829 Snipping Tool 결함과 유사하게 NTLMv2 해시를 노출시킬 수 있습니다."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Windows search: URI 핸들러"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

연구원들이 Windows search: URI 핸들러의 패치되지 않은 취약점을 공개했습니다. 이 취약점은 CVE-2026-33829 Snipping Tool 결함과 유사하게 NTLMv2 해시를 노출시킬 수 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="Windows search: URI 핸들러" >}}

Huntress의 사이버 보안 연구원들이 Windows search: URI 핸들러의 패치되지 않은 취약점 세부 정보를 공개했습니다. 이 취약점으로 인해 공격자가 NTLMv2 해시를 탈취할 수 있습니다. 이 문제는 Windows Snipping Tool의 ms-screensketch: URI 핸들러에서 NTLM 해시를 노출시켰던 CVE-2026-33829 스푸핑 취약점을 연상시킵니다.

{{< ad-banner >}}

새로 식별된 결함은 Windows Search 쿼리를 실행하는 데 사용되는 search: URI 체계에 있습니다. search: URI 핸들러를 트리거하는 악성 링크나 파일을 조작함으로써 공격자는 대상 시스템이 원격 서버에 인증하도록 강제하여 사용자의 NTLMv2 해시를 유출시킬 수 있습니다. 이 해시는 오프라인에서 크랙되거나 릴레이 공격에 사용될 수 있습니다.

발행일 기준으로 Microsoft는 공식 패치를 발표하지 않았습니다. 조직은 업데이트를 모니터링하고 패치가 제공될 때까지 그룹 정책이나 엔드포인트 보안 도구를 통해 search: URI 핸들러를 차단하는 것을 고려해야 합니다.

{{< netrunner-insight >}}

이것은 SOC 분석가가 인증 로그에서 주시해야 하는 전형적인 NTLM 릴레이 벡터입니다. DevSecOps 엔지니어는 자신의 환경에서 URI 핸들러 사용을 즉시 검토하고 NTLMv2 비활성화 또는 SMB 서명 적용과 같은 완화 조치를 적용해야 합니다. Microsoft가 패치할 때까지 search: URI가 자격 증명 탈취의 잠재적 진입점이라고 가정하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
