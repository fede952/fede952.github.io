---
title: "FBI, 러시아 해커들이 피싱 캠페인에서 Signal 백업 복구 키를 노린다고 경고"
date: "2026-06-28T09:56:23Z"
original_date: "2026-06-26T22:06:17"
lang: "ko"
translationKey: "fbi-warns-russian-hackers-target-signal-backup-recovery-keys-in-phishing-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI와 CISA는 러시아 정보기관과 연계된 피싱 공격이 이제 Signal 백업 복구 키를 탈취하여 피해자의 과거 메시지에 접근할 수 있게 한다고 경고합니다."
original_url: "https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/"
source: "BleepingComputer"
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

FBI와 CISA는 러시아 정보기관과 연계된 피싱 공격이 이제 Signal 백업 복구 키를 탈취하여 피해자의 과거 메시지에 접근할 수 있게 한다고 경고합니다.

{{< cyber-report severity="High" source="BleepingComputer" target="Signal 사용자" >}}

FBI와 CISA는 러시아 정보기관의 소행으로 추정되는 피싱 캠페인이 Signal 백업 복구 키를 노리는 방향으로 진화했다는 공동 경고를 발표했습니다. 일반적으로 새 기기에서 메시지 기록을 복원하는 데 사용되는 이 키는 탈취될 경우 공격자가 피해자의 과거 대화 및 연락처에 접근할 수 있게 합니다.

{{< ad-banner >}}

이 캠페인은 처음에 Signal 로그인 자격 증명을 탈취하는 데 초점을 맞췄으나, 이제 복구 키를 유출하는 방향으로 확대되었습니다. 공격자는 가짜 Signal 그룹 초대장이나 보안 알림과 같은 사회공학적 전술을 사용하여 사용자가 복구 키를 공개하도록 속입니다.

민감한 통신에 Signal을 사용하는 조직과 개인은 등록 잠금 및 화면 잠금과 같은 추가 보안 조치를 활성화하고, 복구 키나 로그인 자격 증명을 요청하는 모든 요청의 진위를 확인할 것을 권고합니다.

{{< netrunner-insight >}}

SOC 분석가는 Signal 그룹 초대나 보안 알림을 사칭하는 피싱 미끼를 모니터링해야 합니다. 이러한 미끼는 이제 복구 키를 수확하는 데 사용되고 있습니다. DevSecOps 팀은 다중 인증을 시행하고, 합법적인 서비스는 원치 않는 메시지를 통해 복구 키나 비밀번호를 요청하지 않는다는 점을 사용자에게 교육해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/)**
