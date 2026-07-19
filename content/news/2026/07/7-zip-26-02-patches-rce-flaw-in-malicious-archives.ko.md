---
title: "7-Zip 26.02, 악성 아카이브의 RCE 취약점 패치"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "ko"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip이 버전 26.02를 출시하여 특수 제작된 압축 파일을 열 때 트리거될 수 있는 원격 코드 실행 취약점을 수정했습니다. 즉시 업데이트하세요."
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "7-Zip 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip이 버전 26.02를 출시하여 특수 제작된 압축 파일을 열 때 트리거될 수 있는 원격 코드 실행 취약점을 수정했습니다. 즉시 업데이트하세요.

{{< cyber-report severity="High" source="BleepingComputer" target="7-Zip 사용자" >}}

7-Zip 버전 26.02가 출시되어 공격자가 피해자 시스템에서 임의 코드를 실행할 수 있는 원격 코드 실행(RCE) 취약점을 해결했습니다. 이 결함은 사용자가 악성 페이로드가 포함된 아카이브와 같은 특수 제작된 압축 파일을 열도록 유도함으로써 악용될 수 있습니다.

{{< ad-banner >}}

이 취약점은 널리 사용되는 파일 압축기의 모든 이전 버전에 영향을 미칩니다. 발표에서 CVE 식별자는 공개되지 않았지만, 잠재적인 전체 시스템 손상 가능성으로 인해 심각도는 높은 것으로 간주됩니다. 사용자는 최신 버전으로 즉시 업데이트할 것을 강력히 권장합니다.

7-Zip이 기업 및 소비자 환경 모두에서 널리 사용된다는 점을 고려할 때, 이 패치는 공격 표면을 줄이는 데 중요합니다. 조직은 자동 업데이트 메커니즘 또는 수동 설치를 통해 배포를 우선시해야 합니다.

{{< netrunner-insight >}}

SOC 분석가는 비정상적인 아카이브 파일 활동을 모니터링하고 모든 엔드포인트에서 7-Zip이 업데이트되었는지 확인해야 합니다. DevSecOps 팀은 이 업데이트를 패치 관리 파이프라인에 통합하고 이전 버전의 7-Zip이 중요 시스템에 액세스하지 못하도록 차단하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
