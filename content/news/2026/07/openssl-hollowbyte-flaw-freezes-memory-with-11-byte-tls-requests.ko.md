---
title: "OpenSSL HollowByte 결함, 11바이트 TLS 요청으로 메모리 동결"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "ko"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "OpenSSL의 서비스 거부 버그인 HollowByte는 공격자가 작은 TLS 요청을 사용하여 서버 메모리를 동결시킬 수 있게 합니다. Okta의 Red Team이 이를 보고했으며, CVE 없이 수정 사항이 배포되었습니다."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "glibc 시스템의 OpenSSL 서버"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

OpenSSL의 서비스 거부 버그인 HollowByte는 공격자가 작은 TLS 요청을 사용하여 서버 메모리를 동결시킬 수 있게 합니다. Okta의 Red Team이 이를 보고했으며, CVE 없이 수정 사항이 배포되었습니다.

{{< cyber-report severity="High" source="The Hacker News" target="glibc 시스템의 OpenSSL 서버" >}}

새롭게 공개된 OpenSSL의 서비스 거부 취약점인 HollowByte는 Okta의 Red Team이 명명했으며, 공격자가 TLS 핸드셰이크 데이터 11바이트만으로 서버 메모리를 고갈시킬 수 있습니다. 이 결함은 패치되지 않은 OpenSSL 서버가 도착하지 않는 메시지에 대해 최대 131KB의 메모리를 할당하게 하며, glibc를 사용하는 시스템에서는 프로세스가 재시작될 때까지 해당 메모리가 해제되지 않습니다.

{{< ad-banner >}}

OpenSSL은 2026년 6월에 CVE 식별자를 할당하지 않고, 권고를 발행하지 않으며, 변경 로그에 변경 사항을 기록하지 않은 채 수정 사항을 배포했습니다. 버그를 발견하고 보고한 Okta의 Red Team은 수정 사항이 출시된 후 세부 정보를 공개했습니다. 이 취약점은 glibc 기반 시스템에서 실행되는 OpenSSL 서버에 영향을 미쳐 메모리 고갈 공격에 취약하게 만듭니다.

공격에는 11바이트의 단일 TLS ClientHello만 필요하지만, OpenSSL 프로세스가 장기 실행되고 많은 동시 연결을 처리하는 환경에서는 영향이 심각할 수 있습니다. glibc에서 OpenSSL을 실행하는 조직은 잠재적인 서비스 거부 상황을 방지하기 위해 2026년 6월 업데이트를 우선 적용해야 합니다.

{{< netrunner-insight >}}

이것은 악성 트래픽이 정상적인 TLS 핸드셰이크처럼 보이기 때문에 전통적인 속도 제한을 우회하는 전형적인 리소스 고갈 벡터입니다. SOC 분석가는 OpenSSL 서버의 메모리 사용량 급증을 모니터링해야 하며, DevSecOps 팀은 CVE가 없더라도 2026년 6월 OpenSSL 업데이트가 배포되었는지 확인해야 합니다. CVE가 없다고 해서 운영 위험이 줄어들지는 않습니다. 이를 높은 우선순위의 패치로 취급하십시오.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
