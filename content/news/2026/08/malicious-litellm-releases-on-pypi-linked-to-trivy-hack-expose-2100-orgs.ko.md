---
title: "PyPI의 악성 LiteLLM 릴리스, Trivy 해킹과 연계되어 2,100개 이상의 조직 노출"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "ko"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "PyPI의 두 악성 LiteLLM 패키지가 클라우드 키, SSH 키 등을 탈취했습니다. CloudSEK 데이터에 따르면 2,100개 이상의 조직이 노출되었을 수 있습니다."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "PyPI의 LiteLLM 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PyPI의 두 악성 LiteLLM 패키지가 클라우드 키, SSH 키 등을 탈취했습니다. CloudSEK 데이터에 따르면 2,100개 이상의 조직이 노출되었을 수 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="PyPI의 LiteLLM 사용자" >}}

3월에 PyPI에 두 개의 악성 LiteLLM 릴리스가 게시되어 약 40분 동안 유지되었습니다. 이 패키지에는 자격 증명을 탈취하는 코드가 포함되어 있어, 설치한 모든 시스템에서 클라우드 액세스 키, SSH 개인 키, Kubernetes 토큰, 데이터베이스 비밀번호 등 다양한 비밀 정보를 수집하도록 설계되었습니다.

{{< ad-banner >}}

위협 인텔리전스 기업 CloudSEK는 공격자가 확보한 약 434,000개의 파일로 구성된 데이터 세트를 입수했습니다. 이 데이터 세트를 분석한 결과, 노출이 2,100개 이상의 조직에 영향을 미칠 수 있어 공격의 잠재적 규모를 보여줍니다.

이번 사건은 이전 Trivy 해킹과 연관되어 조율된 공급망 공격임을 시사합니다. 영향을 받은 기간 동안 PyPI에서 LiteLLM을 설치한 조직은 노출된 모든 자격 증명을 즉시 교체하고 무단 액세스 징후를 조사해야 합니다.

{{< netrunner-insight >}}

이번 사건은 소프트웨어 공급망 경계의 중요성을 강조합니다. SOC 분석가는 악성 LiteLLM 버전의 설치를 모니터링하고 잠재적으로 노출된 비밀 정보에 대한 자격 증명 교체를 우선시해야 합니다. DevSecOps 팀은 엄격한 패키지 무결성 검사를 시행하고 해시가 포함된 개인 미러 또는 잠금 파일을 사용하여 이러한 위험을 완화해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
