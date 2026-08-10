---
title: "TONTOU CPU 공격이 Spectre v2 완화 조치를 우회하고 Linux 비밀번호 해시를 유출한다"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "ko"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "연구진이 최근 Spectre v2 완화 조치를 우회하는 TONTOU 공격을 개발했으며, Linux 시스템에서 비밀번호 해시를 포함한 비밀 정보를 성공적으로 유출했다."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Linux 시스템"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

연구진이 최근 Spectre v2 완화 조치를 우회하는 TONTOU 공격을 개발했으며, Linux 시스템에서 비밀번호 해시를 포함한 비밀 정보를 성공적으로 유출했다.

{{< cyber-report severity="High" source="BleepingComputer" target="Linux 시스템" >}}

보안 연구원들이 Spectre v2 취약점에 대한 최근 완화 조치를 우회하는 'TONTOU'라는 새로운 추측 실행 공격을 공개했다. 이 공격은 이전에 부채널 누출을 방지하기 위해 패치된 CPU의 분기 예측 메커니즘을 대상으로 한다. 연구원들은 이러한 방어의 허점을 악용하여 Linux 머신의 커널 메모리에서 민감한 데이터를 추출할 수 있었다.

{{< ad-banner >}}

개념 증명 익스플로잇은 대상 시스템에서 비밀번호 해시를 성공적으로 유출함으로써 이 문제의 심각성을 입증한다. 이는 이 공격이 사용자 자격 증명을 손상시키고 잠재적으로 권한을 상승시키는 데 사용될 수 있음을 나타낸다. 이러한 발견은 이전 수정에도 불구하고 새로운 변형이 계속 등장함에 따라 추측 실행 부채널 공격을 완전히 완화하는 것이 여전히 어려운 과제임을 강조한다.

연구원들은 아직 전체 기술적 세부 사항을 공개하지 않았지만, 이 연구는 CPU 보안에 대한 지속적인 경계의 필요성을 강조한다. 시스템 관리자는 CPU 공급업체와 Linux 배포판의 업데이트를 모니터링하고, 커널 주소 공간 레이아웃 무작위화(KASLR) 및 마이크로코드 업데이트와 같은 추가 강화 조치를 고려하는 것이 좋다.

{{< netrunner-insight >}}

이 공격은 추측 실행 취약점이 완전히 해결되지 않았음을 상기시킨다. SOC 분석가는 패치 적용을 우선시하고 악용 징후를 모니터링해야 하며, DevSecOps 엔지니어는 부채널 위험에 대한 위협 모델을 검토해야 한다. 비밀번호 해시 유출 가능성을 고려할 때 Linux 커널 업데이트와 CPU 마이크로코드에 즉각적인 주의를 기울여야 한다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
