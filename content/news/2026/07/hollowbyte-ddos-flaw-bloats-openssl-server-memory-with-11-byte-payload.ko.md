---
title: "HollowByte DDoS 결함, 11바이트 페이로드로 OpenSSL 서버 메모리 부풀리기"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "ko"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "HollowByte로 명명된 취약점은 인증되지 않은 공격자가 단 11바이트의 악성 페이로드로 OpenSSL 서버에 서비스 거부(DoS) 상태를 유발할 수 있게 합니다."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "OpenSSL 서버"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

HollowByte로 명명된 취약점은 인증되지 않은 공격자가 단 11바이트의 악성 페이로드로 OpenSSL 서버에 서비스 거부(DoS) 상태를 유발할 수 있게 합니다.

{{< cyber-report severity="High" source="BleepingComputer" target="OpenSSL 서버" >}}

HollowByte라는 새로 발견된 취약점은 인증되지 않은 공격자가 단 11바이트의 특수 제작된 페이로드를 전송하여 OpenSSL 서버에 서비스 거부(DoS) 상태를 유발할 수 있게 합니다. 이 결함은 메모리 할당 비효율성을 악용하여 서버 메모리를 부풀리고 결국 가용 자원을 고갈시킵니다.

{{< ad-banner >}}

이 공격은 인증이 필요하지 않으며 원격으로 실행될 수 있어, 안전한 통신을 위해 OpenSSL에 의존하는 모든 조직에 심각한 위협이 됩니다. 최소한의 페이로드 크기로 인해 공격자는 제한된 대역폭으로 영향력을 증폭시켜 최소한의 노력으로 서버를 압도할 수 있습니다.

아직 CVE 식별자가 할당되지 않았지만, 이 취약점은 OpenSSL 프로젝트에 공개되었으며 패치가 예상됩니다. 그동안 관리자는 메모리 사용량을 모니터링하고 속도 제한 또는 침입 탐지 규칙을 구현하여 잠재적 악용을 완화하는 것이 좋습니다.

{{< netrunner-insight >}}

SOC 분석가에게 이는 전통적인 볼류메트릭 방어를 우회할 수 있는 전형적인 저대역폭, 고영향 DoS 벡터입니다. DevSecOps 팀은 패치가 제공되는 즉시 우선 적용하고, 비정상적인 성장을 감지하기 위해 메모리 모니터링 알림을 배포하는 것을 고려해야 합니다. 11바이트 페이로드는 위협 탐지 규칙에 포함시키기에 이상적인 후보입니다.

{{< /netrunner-insight >}}

---

**[BleepingComputer에서 전체 기사 읽기 ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
