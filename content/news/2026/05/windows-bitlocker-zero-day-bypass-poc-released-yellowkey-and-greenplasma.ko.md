---
title: "Windows BitLocker 제로데이 우회 PoC 공개: YellowKey 및 GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "ko"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "두 가지 패치되지 않은 Windows 취약점(YellowKey: BitLocker 우회, GreenPlasma: 권한 상승)에 대한 개념 증명 익스플로잇이 공개되어 암호화된 드라이브에 위협이 되고 있습니다."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Windows BitLocker로 보호된 드라이브"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

두 가지 패치되지 않은 Windows 취약점(YellowKey: BitLocker 우회, GreenPlasma: 권한 상승)에 대한 개념 증명 익스플로잇이 공개되어 암호화된 드라이브에 위협이 되고 있습니다.

{{< cyber-report severity="High" source="BleepingComputer" target="Windows BitLocker로 보호된 드라이브" >}}

한 사이버보안 연구원이 YellowKey 및 GreenPlasma라고 명명된 두 가지 패치되지 않은 Microsoft Windows 취약점에 대한 개념 증명(PoC) 익스플로잇을 공개했습니다. YellowKey는 적절한 인증 없이 보호된 드라이브의 데이터에 접근할 수 있게 하는 BitLocker 우회 취약점이며, GreenPlasma는 공격자가 손상된 시스템에서 상승된 권한을 얻을 수 있게 하는 권한 상승 결함입니다.

{{< ad-banner >}}

이러한 PoC의 공개로 위협 행위자들이 해당 기술을 무기화할 수 있게 되어 익스플로잇 위험이 증가합니다. BitLocker를 전체 디스크 암호화에 사용하는 조직은 노출 정도를 평가하고 TPM+PIN 보호 활성화 또는 사전 부팅 인증 사용과 같은 추가 보안 제어를 고려해야 합니다.

Microsoft는 아직 이러한 취약점에 대한 패치를 출시하지 않아 수정 사항이 배포될 때까지 시스템이 노출된 상태로 남아 있습니다. 보안 팀은 암호화된 드라이브에 대한 비정상적인 접근 패턴을 모니터링하고, 가능한 경우 불필요한 부팅 옵션 비활성화 또는 강력한 PIN 정책 시행과 같은 해결 방법을 적용해야 합니다.

{{< netrunner-insight >}}

SOC 분석가의 경우, BitLocker로 보호된 드라이브에 대한 무단 접근 시도 및 권한 상승 이벤트 모니터링을 우선시하십시오. DevSecOps 엔지니어는 공개된 PoC에 대해 환경을 테스트하여 취약한 구성을 식별하고 Secure Boot 및 측정 부팅 로그와 같은 완화 제어를 구현해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
