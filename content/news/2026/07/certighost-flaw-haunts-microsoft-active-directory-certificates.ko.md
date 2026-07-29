---
title: "'Certighost' 취약점, Microsoft Active Directory 인증서에 위협"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "ko"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft가 Active Directory 환경에서 권한 상승을 허용하는 높은 심각도의 취약점을 패치했습니다. SOC 분석가는 패치 적용을 최우선으로 해야 합니다."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Microsoft Active Directory Certificate Services"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft가 Active Directory 환경에서 권한 상승을 허용하는 높은 심각도의 취약점을 패치했습니다. SOC 분석가는 패치 적용을 최우선으로 해야 합니다.

{{< cyber-report severity="High" source="Dark Reading" target="Microsoft Active Directory Certificate Services" >}}

Microsoft는 'Certighost'로 명명된 Active Directory Certificate Services의 높은 심각도 취약점을 패치했습니다. 이 취약점은 공격자가 권한을 상승시켜 Active Directory 환경을 손상시킬 수 있습니다. 이 결함은 2026년 7월 28일 Dark Reading에 의해 공개되었습니다.

{{< ad-banner >}}

이 취약점은 인증서 등록 프로세스에 영향을 미쳐, 낮은 수준의 접근 권한을 가진 위협 행위자가 도메인 관리자로 권한을 상승시킬 수 있게 합니다. 이는 AD 인프라의 완전한 손상, 인증서 위조, 모든 사용자나 장치로의 가장으로 이어질 수 있습니다.

Microsoft Active Directory Certificate Services를 사용하는 조직은 즉시 최신 보안 업데이트를 적용해야 합니다. 이 취약점은 AD 환경 내에서 신뢰를 유지하는 데 있어 인증서 서비스의 중요성을 강조합니다.

{{< netrunner-insight >}}

이것은 전형적인 AD 인증서 서비스 공격 벡터입니다. 인증서 템플릿이 강화되고 등록 권한이 엄격하게 통제되도록 하십시오. 즉시 패치하고 비정상적인 인증서 요청이나 권한 상승을 모니터링하십시오.

{{< /netrunner-insight >}}

---

**[Dark Reading에서 전체 기사 읽기 ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
