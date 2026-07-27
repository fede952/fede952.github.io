---
title: "GitLab RCE PoC 공개: 인증된 사용자가 Git 사용자로 명령 실행 가능"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "ko"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "GitLab 원격 코드 실행 취약점에 대한 개념 증명 익스플로잇이 공개되어 패치되지 않은 자체 관리형 18.11.3 서버를 대상으로 합니다. 인증된 사용자가 git 사용자로 명령을 실행할 수 있습니다."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab 자체 관리형 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

GitLab 원격 코드 실행 취약점에 대한 개념 증명 익스플로잇이 공개되어 패치되지 않은 자체 관리형 18.11.3 서버를 대상으로 합니다. 인증된 사용자가 git 사용자로 명령을 실행할 수 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab 자체 관리형 18.11.3" >}}

2026년 7월 24일, depthfirst의 보안 연구원들이 GitLab 원격 코드 실행 취약점에 대한 작동하는 개념 증명 익스플로잇을 공개했습니다. GitLab이 2026년 6월 10일에 패치한 이 결함은 프로젝트에 푸시 접근 권한이 있는 모든 인증된 사용자가 업데이트를 적용하지 않은 자체 관리형 GitLab 18.11.3 서버에서 git 사용자로 임의 명령을 실행할 수 있도록 합니다.

{{< ad-banner >}}

이 익스플로잇은 프로젝트에 커밋된 조작된 Jupyter 노트북을 활용합니다. 공격자가 커밋 차이점을 열면 악성 노트북이 힙 누수를 트리거하여 명령 실행을 가능하게 합니다. 이 기술은 일반적인 인증 제어를 우회하며 표준 프로젝트 접근 권한 이상의 특별한 권한이 필요하지 않습니다.

자체 관리형 GitLab 인스턴스를 운영하는 조직은 6월 10일 패치를 적용했는지 즉시 확인해야 합니다. 익스플로잇 코드의 공개적 가용성은 특히 인터넷에 노출된 인스턴스에서 적극적인 악용 위험을 증가시킵니다. 블루 팀은 비정상적인 Jupyter 노트북 커밋과 예상치 못한 git 사용자 활동을 모니터링해야 합니다.

{{< netrunner-insight >}}

이 익스플로잇은 자체 관리형 CI/CD 플랫폼에서 패치 지연의 위험을 강조합니다. SOC 분석가는 비정상적인 git 사용자 프로세스와 예상치 못한 Jupyter 노트북 업로드를 탐지하는 데 우선순위를 두어야 합니다. DevSecOps 팀은 GitLab에 대한 엄격한 패치 기간을 시행하고 네트워크 분할을 고려하여 자체 관리형 인스턴스의 노출을 제한해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
