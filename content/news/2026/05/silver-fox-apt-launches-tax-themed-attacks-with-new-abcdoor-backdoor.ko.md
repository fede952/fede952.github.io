---
title: "실버 폭스 APT, 세금 테마 공격으로 새로운 ABCDoor 백도어 배포"
date: "2026-05-05T09:10:11Z"
original_date: "2026-05-04T14:39:26"
lang: "ko"
translationKey: "silver-fox-apt-launches-tax-themed-attacks-with-new-abcdoor-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "중국 지원을 받는 실버 폭스, 인도와 러시아를 대상으로 세금 테마 피싱 공격 전개, ABCDoor 백도어 및 ValleyRAT 악성코드 유포"
original_url: "https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia"
source: "Dark Reading"
severity: "High"
target: "인도 및 러시아의 조직"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

중국 지원을 받는 실버 폭스, 인도와 러시아를 대상으로 세금 테마 피싱 공격 전개, ABCDoor 백도어 및 ValleyRAT 악성코드 유포

{{< cyber-report severity="High" source="Dark Reading" target="인도 및 러시아의 조직" >}}

중국 지원을 받는 고급 지속 위협 그룹 실버 폭스(Silver Fox)가 세금 테마의 사회공학적 기법을 활용하여 인도와 러시아의 조직을 표적으로 삼는 새로운 캠페인을 시작했습니다. 이 공격은 다양한 부문을 대상으로 한 1,600개 이상의 사회공학적 메시지를 포함하며, 이전에 문서화되지 않은 ABCDoor 백도어와 ValleyRAT 악성코드를 유포합니다.

{{< ad-banner >}}

ABCDoor 백도어는 실버 폭스의 무기고에 새로 추가된 도구로, 지속적인 접근 권한을 확보하고 데이터를 유출하도록 설계되었습니다. 알려진 원격 접근 트로이목마인 ValleyRAT도 이 공격에 사용됩니다. 이 캠페인은 그룹이 금융 및 정부 기관에 지속적으로 초점을 맞추고 있음을 보여주며, 시의적절한 세금 테마를 활용하여 피해자의 참여를 유도합니다.

보안 연구원들은 영향을 받는 지역의 조직에 이메일 필터링 및 사용자 인식 교육을 강화할 것을 촉구합니다. 공격이 사회공학에 크게 의존하기 때문입니다. 캠페인과 관련된 침해 지표(IOC)를 모니터링하고, 새로운 백도어와 RAT를 탐지하기 위해 네트워크 방어 체계를 업데이트해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 세금 테마 피싱 이메일 모니터링을 우선시하고 ABCDoor 백도어의 네트워크 시그니처에 대한 행동 탐지 규칙을 배포해야 합니다. DevSecOps 팀은 엔드포인트 탐지 및 대응(EDR) 도구가 ValleyRAT의 지속성 메커니즘을 식별하도록 조정하고, 실버 폭스와 관련된 알려진 C2 인프라를 차단하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[Dark Reading에서 전체 기사 읽기 ›](https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia)**
