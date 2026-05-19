---
title: "미니 샤이훌루드 캠페인, 관리자 계정을 통해 @antv npm 패키지 손상"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "ko"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "공격자들이 @antv 관리자 계정 'atool'을 손상시켜 주간 다운로드 110만 건의 echarts-for-react를 포함한 악성 npm 패키지를 푸시하고 있습니다. 이는 진행 중인 미니 샤이훌루드 공급망 공격의 일환입니다."
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "@antv npm 생태계"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

공격자들이 @antv 관리자 계정 'atool'을 손상시켜 주간 다운로드 110만 건의 echarts-for-react를 포함한 악성 npm 패키지를 푸시하고 있습니다. 이는 진행 중인 미니 샤이훌루드 공급망 공격의 일환입니다.

{{< cyber-report severity="High" source="The Hacker News" target="@antv npm 생태계" >}}

사이버보안 연구원들이 @antv npm 생태계를 대상으로 한 새로운 소프트웨어 공급망 공격 캠페인을 식별했습니다. 공격자들은 npm 관리자 계정 'atool'을 손상시켜 여러 패키지의 악성 버전을 게시했으며, 여기에는 주간 다운로드 약 110만 건의 널리 사용되는 React 래퍼인 echarts-for-react가 포함됩니다.

{{< ad-banner >}}

이 캠페인은 이전에 다른 오픈소스 생태계를 표적으로 삼았던 진행 중인 미니 샤이훌루드 공격의 일부입니다. 손상된 패키지에는 민감한 데이터를 유출하거나 개발 환경에 백도어를 설치하도록 설계된 악성 코드가 포함되어 있을 가능성이 높습니다.

@antv 패키지를 사용하는 조직은 즉시 종속성에서 손상 징후를 감사하고, 자격 증명을 교체하며, 잠금 파일의 최근 변경 사항을 검토해야 합니다. 영향을 받은 패키지의 전체 범위와 정확한 페이로드는 현재 조사 중입니다.

{{< netrunner-insight >}}

이번 공격은 패키지 무결성 검증, 관리자 계정에 대한 다중 인증, 자동화된 종속성 스캐닝과 같은 공급망 보안 조치의 중요성을 강조합니다. SOC 분석가는 빌드 파이프라인에서 비정상적인 아웃바운드 트래픽 모니터링을 우선시해야 하며, DevSecOps 팀은 패키지 게시 계정에 대한 엄격한 접근 제어를 시행해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
