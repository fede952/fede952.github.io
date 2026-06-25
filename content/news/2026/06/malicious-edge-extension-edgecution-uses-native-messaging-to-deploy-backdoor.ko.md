---
title: "악성 Edge 확장 프로그램 'Edgecution', 네이티브 메시징을 이용해 백도어 배포"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "ko"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "악성 Microsoft Edge 확장 프로그램 'Edgecution'이 네이티브 메시징을 통해 브라우저 샌드박스를 탈출하여 랜섬웨어 공격에서 Python 기반 백도어를 배포합니다."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Edge 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

악성 Microsoft Edge 확장 프로그램 'Edgecution'이 네이티브 메시징을 통해 브라우저 샌드박스를 탈출하여 랜섬웨어 공격에서 Python 기반 백도어를 배포합니다.

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Edge 사용자" >}}

악성 Microsoft Edge 확장 프로그램 'Edgecution'이 랜섬웨어 공격에서 관찰되었으며, 브라우저의 네이티브 메시징 API를 활용하여 샌드박스를 탈출하고 호스트 시스템에서 임의 코드를 실행합니다. 이 확장 프로그램은 Python 기반 백도어를 배포하는 브리지 역할을 하여 지속적인 접근과 추가 악성 활동을 가능하게 합니다.

{{< ad-banner >}}

공격 체인은 악성 확장 프로그램 설치로 시작되며, 이후 네이티브 메시징을 남용하여 브라우저 샌드박스 외부의 네이티브 애플리케이션과 통신합니다. 이 기술은 일반적인 브라우저 보안 경계를 우회하여 공격자가 명령을 실행하고 랜섬웨어를 포함한 추가 페이로드를 드롭할 수 있게 합니다.

보안 연구원들은 이 방법이 합법적인 브라우저 기능을 악용하기 때문에 특히 교묘하며, 기존 엔드포인트 보안 솔루션으로 탐지하기 어렵다고 강조합니다. 조직은 승인되지 않은 브라우저 확장 프로그램을 모니터링하고 가능한 경우 네이티브 메시징 권한을 제한하는 것이 좋습니다.

{{< netrunner-insight >}}

이 공격은 브라우저 확장 프로그램 설치와 네이티브 메시징 활동 모니터링의 중요성을 강조합니다. SOC 분석가는 비정상적인 확장 프로그램 동작과 예상치 못한 네이티브 호스트 통신을 찾아야 하며, DevSecOps 팀은 엄격한 확장 프로그램 허용 목록을 적용하고 불필요한 네이티브 메시징 호스트를 비활성화해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
