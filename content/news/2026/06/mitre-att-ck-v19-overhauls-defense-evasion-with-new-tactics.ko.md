---
title: "MITRE ATT&CK v19, 방어 회피를 새로운 전술로 대대적으로 개편"
date: "2026-06-23T10:34:05Z"
original_date: "2026-06-23T10:14:50"
lang: "ko"
translationKey: "mitre-att-ck-v19-overhauls-defense-evasion-with-new-tactics"
author: "NewsBot (Validated by Federico Sella)"
description: "MITRE ATT&CK v19는 구조적 변경을 도입하여 방어 회피(TA0005)를 폐기하고 Stealthee와 Impair Defenses를 추가합니다. 마이그레이션 가이드가 제공됩니다."
original_url: "https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/"
source: "Cybersecurity360"
severity: "Info"
target: "MITRE ATT&CK 프레임워크 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

MITRE ATT&CK v19는 구조적 변경을 도입하여 방어 회피(TA0005)를 폐기하고 Stealthee와 Impair Defenses를 추가합니다. 마이그레이션 가이드가 제공됩니다.

{{< cyber-report severity="Info" source="Cybersecurity360" target="MITRE ATT&CK 프레임워크 사용자" >}}

MITRE가 ATT&CK 프레임워크 버전 19를 출시하여 중요한 구조적 수정을 도입했습니다. 가장 주목할 만한 변경 사항은 방어 회피 전술(TA0005)의 폐기이며, 이는 Stealthee와 Impair Defenses라는 두 가지 새로운 전술로 대체됩니다. 이번 재구성은 탐지 회피 및 방어 방해와 관련된 적대적 행동을 보다 세분화하여 분류하는 것을 목표로 합니다.

{{< ad-banner >}}

이 업데이트에는 조직이 위협 모델과 탐지 규칙을 기존 전술에서 새로운 전술로 전환하는 데 도움이 되는 마이그레이션 가이드가 포함되어 있습니다. 실무자는 방어 회피에 대한 현재 매핑을 검토하고 적절한 새 전술에 기술을 재할당하여 적용 범위를 유지하는 것이 좋습니다.

이번 릴리스와 관련된 특정 CVE나 취약점은 없지만, 프레임워크 업데이트는 SOC 운영 및 위협 헌팅에 영향을 미칩니다. 팀은 MITRE ATT&CK 참조를 업데이트하고 폐기된 전술 ID를 참조하는 분석을 조정해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, 이는 TA0005를 참조하는 탐지 규칙과 위협 헌팅 쿼리를 업데이트해야 함을 의미합니다. DevSecOps 엔지니어는 CI/CD 파이프라인 보안 매핑을 검토하여 새로운 전술과 일치하는지 확인해야 합니다. 마이그레이션 가이드는 전환 중 적용 범위의 공백을 방지하는 데 필수적입니다.

{{< /netrunner-insight >}}

---

**[Cybersecurity360에서 전체 기사 읽기 ›](https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/)**
