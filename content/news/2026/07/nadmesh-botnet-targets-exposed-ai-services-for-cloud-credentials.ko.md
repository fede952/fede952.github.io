---
title: "NadMesh 봇넷, 클라우드 자격 증명을 노려 노출된 AI 서비스 표적"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "ko"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "Go 기반의 새로운 봇넷 NadMesh가 ComfyUI, Ollama와 같은 노출된 AI 플랫폼을 사냥하여 AWS 키와 Kubernetes 토큰을 탈취합니다. 3,800개 이상의 키가 탈취된 것으로 알려졌습니다."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "노출된 AI 서비스 (ComfyUI, Ollama, n8n 등)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Go 기반의 새로운 봇넷 NadMesh가 ComfyUI, Ollama와 같은 노출된 AI 플랫폼을 사냥하여 AWS 키와 Kubernetes 토큰을 탈취합니다. 3,800개 이상의 키가 탈취된 것으로 알려졌습니다.

{{< cyber-report severity="High" source="The Hacker News" target="노출된 AI 서비스 (ComfyUI, Ollama, n8n 등)" >}}

Go로 작성된 NadMesh라는 새로운 봇넷이 2026년 7월 초에 등장하여 노출된 AI 서비스를 표적으로 클라우드 자격 증명과 Kubernetes 토큰을 탈취하고 있습니다. 봇넷의 운영자 대시보드에는 3,811개의 고유 AWS 키가 수집된 것으로 나타나 상당한 운영 규모를 시사합니다. NadMesh는 Shodan 기반 수집기를 사용하여 ComfyUI, Ollama, n8n, Open WebUI, Langflow, Gradio 등 인기 있는 AI 도구의 취약한 인스턴스로 스캔 큐를 지속적으로 채웁니다.

{{< ad-banner >}}

이러한 AI 플랫폼은 개발 팀이 적절한 보안 강화 없이 신속하게 배포하는 경우가 많아 인터넷에 노출됩니다. 봇넷은 이러한 방화벽 보호 부재를 악용하여 액세스 권한을 얻고 민감한 자격 증명을 추출합니다. AI 서비스에 대한 집중은 공격자 표적이 고가치 클라우드 인프라와 머신러닝 파이프라인으로 이동하고 있음을 시사합니다.

이러한 AI 도구를 실행하는 조직은 즉시 노출을 감사하고, 네트워크 액세스를 제한하며, 손상되었을 수 있는 모든 자격 증명을 교체해야 합니다. NadMesh 봇넷은 잘못 구성된 AI 서비스가 자격 증명 탈취 및 측면 이동의 주요 표적이 되는 증가하는 위협 환경을 보여줍니다.

{{< netrunner-insight >}}

SOC 분석가를 위한 조언: 환경에서 노출된 ComfyUI, Ollama 및 유사한 AI 서비스를 스캔하는 것을 우선시하십시오. DevSecOps 팀은 이러한 도구를 배포하기 전에 네트워크 세분화 및 방화벽 규칙을 적용해야 합니다. NadMesh 봇넷은 보안 검토 없이 빠른 배포가 자동화된 자격 증명 수집을 초래한다는 명확한 경고입니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
