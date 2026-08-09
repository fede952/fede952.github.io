---
title: "TrueConf 설치 프로그램이 Head Mare 공급망 공격에서 백도어 처리됨"
date: "2026-08-09T07:48:35Z"
original_date: "2026-08-08T14:16:23"
lang: "ko"
translationKey: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
slug: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Head Mare는 패치되지 않은 TrueConf 서버를 악용하여 클라이언트 설치 프로그램을 백도어 버전으로 교체하고 피해자에게 악성코드를 전달합니다."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/"
source: "BleepingComputer"
severity: "High"
target: "TrueConf 화상 회의 서버"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Head Mare는 패치되지 않은 TrueConf 서버를 악용하여 클라이언트 설치 프로그램을 백도어 버전으로 교체하고 피해자에게 악성코드를 전달합니다.

{{< cyber-report severity="High" source="BleepingComputer" target="TrueConf 화상 회의 서버" >}}

해커티비스트 그룹 Head Mare는 패치되지 않은 TrueConf 화상 회의 서버의 취약점을 적극적으로 악용하고 있습니다. 이러한 서버를 손상시킴으로써 공격자는 합법적인 클라이언트 설치 프로그램을 백도어가 포함된 악성 버전으로 교체할 수 있습니다.

{{< ad-banner >}}

사용자가 트로이 목마화된 설치 프로그램을 다운로드하여 실행하면 백도어가 시스템에 배포되어 공격자에게 원격 액세스 및 제어 권한을 부여할 수 있습니다. 이러한 공급망 공격은 사용자가 공식 소프트웨어 배포 채널에 두는 신뢰를 이용합니다.

TrueConf를 사용하는 조직은 설치 프로그램의 무결성을 즉시 확인하고 모든 서버가 알려진 취약점에 대해 패치되었는지 확인해야 합니다. 이 공격은 소프트웨어 배포에서 비정상적인 동작을 모니터링하고 강력한 패치 관리 관행을 유지하는 것의 중요성을 강조합니다.

{{< netrunner-insight >}}

이 사건은 공급망 경계의 필요성을 강조합니다: 공식 소스에서 다운로드한 설치 프로그램이라도 항상 체크섬과 서명을 확인하십시오. SOC 팀의 경우 설치 후 비정상적인 네트워크 연결이나 백도어 활성화를 나타낼 수 있는 프로세스를 모니터링하십시오. 패치 관리는 중요합니다—패치되지 않은 서버는 공격자에게 쉬운 표적입니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/)**
