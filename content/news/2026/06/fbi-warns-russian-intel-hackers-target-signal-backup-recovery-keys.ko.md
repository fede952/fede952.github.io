---
title: "FBI, 러시아 정보기관 해커들이 Signal 백업 복구 키를 노린다고 경고"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "ko"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI와 CISA 경고 업데이트: 러시아 정보기관의 피싱 공격이 이제 Signal 백업 복구 키를 탈취하여 개인 메시지를 읽고 계정을 장악합니다."
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "Signal 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI와 CISA 경고 업데이트: 러시아 정보기관의 피싱 공격이 이제 Signal 백업 복구 키를 탈취하여 개인 메시지를 읽고 계정을 장악합니다.

{{< cyber-report severity="High" source="The Hacker News" target="Signal 사용자" >}}

FBI와 CISA가 3월에 발표한 러시아 정보기관의 Signal 계정을 대상으로 한 피싱 캠페인에 대한 경고를 업데이트했습니다. 공격자들은 새로운 단계를 추가했습니다. 이제 대상자에게 Signal 백업 복구 키를 넘기도록 유도합니다. 키를 획득하면 공격자는 계정의 백업을 복원하고, 개인 및 그룹 메시지 기록을 읽고, 계정을 완전히 장악할 수 있습니다.

{{< ad-banner >}}

이 키는 초기 침해 이후에도 유효하여 지속적인 접근을 가능하게 합니다. 이 기술은 전통적인 이중 인증을 우회하는데, 복구 키가 합법적인 계정 복원을 위해 설계되었기 때문입니다. 권고문은 사용자가 복구 키를 절대 공유하지 말고 등록 잠금 및 기타 보안 기능을 활성화해야 한다고 강조합니다.

조직은 이 특정 피싱 벡터에 대해 사용자를 교육하고 민감한 통신에 대한 추가 확인 단계를 구현하는 것을 고려해야 합니다. 이 위협은 러시아 정보기관 행위자에 의한 것으로, 캠페인의 지정학적 맥락을 강조합니다.

{{< netrunner-insight >}}

이것은 보안 기능을 표적으로 삼은 사회 공학의 전형적인 사례입니다. SOC 분석가는 비정상적인 계정 복구 요청을 모니터링하고 사용자에게 Signal의 백업 복구 키를 절대 공유해서는 안 된다고 교육해야 합니다. DevSecOps 팀은 중요 통신에 피싱 저항 인증을 통합하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
