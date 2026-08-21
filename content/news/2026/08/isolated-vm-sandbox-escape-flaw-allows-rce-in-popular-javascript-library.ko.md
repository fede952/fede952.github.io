---
title: "isolated-vm 샌드박스 이스케이프 결함으로 인기 JavaScript 라이브러리에서 RCE 가능"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "ko"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "isolated-vm의 치명적인 결함으로 샌드박스 처리된 JavaScript가 호스트로 이스케이프하여 잠재적인 원격 코드 실행이 가능해집니다. 7.0.0까지의 모든 버전이 영향을 받습니다."
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "isolated-vm JavaScript 샌드박스 라이브러리"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

isolated-vm의 치명적인 결함으로 샌드박스 처리된 JavaScript가 호스트로 이스케이프하여 잠재적인 원격 코드 실행이 가능해집니다. 7.0.0까지의 모든 버전이 영향을 받습니다.

{{< cyber-report severity="Critical" source="The Hacker News" target="isolated-vm JavaScript 샌드박스 라이브러리" >}}

널리 사용되는 오픈소스 JavaScript 샌드박스 라이브러리인 isolated-vm에서 치명적인 보안 취약점이 공개되었습니다. 이 라이브러리는 GitHub에서 2,900개 이상의 스타와 190개의 포크를 보유하고 있습니다. GHSA-864f-rcv7-6rh4로 추적되는 이 결함은 공격자가 샌드박스 환경을 이스케이프하여 호스트 시스템에서 임의 코드를 실행할 수 있게 합니다. 7.0.0을 포함한 모든 버전이 영향을 받습니다.

{{< ad-banner >}}

이 취약점은 신뢰할 수 없는 JavaScript 코드를 실행하기 위한 안전한 경계를 제공하도록 설계된 isolated-vm의 특성상 특히 우려됩니다. 샌드박스 이스케이프에 성공하면 호스트 애플리케이션과 기반 인프라가 손상될 수 있습니다. 아직 CVE 식별자가 할당되지 않았지만, 이 권고는 이 라이브러리를 사용하는 개발자들의 즉각적인 주의가 필요함을 강조합니다.

isolated-vm에 의존하는 조직은 패치를 모니터링하고 신뢰할 수 없는 코드 실행을 제한하거나 추가 격리 계층을 적용하는 등의 완화 통제를 고려해야 합니다. 현재 CVE가 없다고 해서 심각성이 줄어들지는 않으며, 개념 증명 익스플로잇이 이미 보안 커뮤니티에 유포되고 있을 수 있습니다.

{{< netrunner-insight >}}

이 샌드박스 이스케이프는 목적에 맞게 설계된 격리 도구조차 치명적인 결함을 가질 수 있다는 사실을 극명하게 보여줍니다. SOC 분석가는 isolated-vm을 사용하는 모든 애플리케이션을 목록화하고 수정 사항이 제공되는 대로 패치 적용을 우선시해야 합니다. DevSecOps 팀은 또한 샌드박싱 전략을 검토하고 샌드박스를 별도의 컨테이너나 VM에서 실행하여 폭발 반경을 제한하는 등의 심층 방어를 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
