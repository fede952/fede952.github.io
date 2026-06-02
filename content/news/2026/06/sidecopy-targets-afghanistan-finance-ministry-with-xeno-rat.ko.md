---
title: "SideCopy, 아프가니스탄 재무부를 Xeno RAT로 표적 삼다"
date: "2026-06-02T11:14:31Z"
original_date: "2026-06-02T09:05:40"
lang: "ko"
translationKey: "sidecopy-targets-afghanistan-finance-ministry-with-xeno-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "파키스탄과 연계된 SideCopy 그룹이 파슈토어 LNK 파일을 이용한 스피어 피싱으로 아프가니스탄 재무부를 공격해 Xeno RAT를 유포하고 있습니다."
original_url: "https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html"
source: "The Hacker News"
severity: "High"
target: "아프가니스탄 재무부"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

파키스탄과 연계된 SideCopy 그룹이 파슈토어 LNK 파일을 이용한 스피어 피싱으로 아프가니스탄 재무부를 공격해 Xeno RAT를 유포하고 있습니다.

{{< cyber-report severity="High" source="The Hacker News" target="아프가니스탄 재무부" >}}

사이버보안 연구원들이 파키스탄과 연계된 SideCopy 그룹이 아프가니스탄 재무부를 표적으로 삼은 스피어 피싱 캠페인을 공개했습니다. 공격은 악성 LNK 파일이 포함된 ZIP 아카이브로 시작되며, 이 파일은 정교하게 제작된 파슈토어 파일명을 사용해 피해자를 유인합니다.

{{< ad-banner >}}

전달된 페이로드는 오픈소스 원격 접속 트로이목마인 Xeno RAT입니다. 이 도구는 공격자에게 감염된 시스템에 대한 광범위한 제어권을 제공하여 데이터 탈취와 추가 네트워크 침해를 가능하게 합니다. 파슈토어 사용은 아프가니스탄 내 현지 표적에 초점을 맞추고 있음을 시사합니다.

SideCopy는 역사적으로 파키스탄 기반 위협 행위자와 연계되어 있으며 남아시아 개체를 표적으로 삼아 왔습니다. 이 캠페인은 지역에서 진행 중인 지정학적 사이버 스파이 활동을 강조하며, 정부 부처가 정보 수집의 주요 표적이 되고 있음을 보여줍니다.

{{< netrunner-insight >}}

SOC 분석가는 정부 기관을 표적으로 한 피싱 이메일에서 파슈토어 파일명을 가진 LNK 파일과 ZIP 아카이브를 모니터링해야 합니다. DevSecOps 팀은 특히 아프간 또는 남아시아 문제와 관련된 조직의 경우 엄격한 이메일 첨부 파일 필터링과 사용자 인식 교육을 시행해야 합니다. Xeno RAT의 오픈소스 특성상 탐지 시그니처가 제공되므로 EDR 솔루션을 업데이트해야 합니다.

{{< /netrunner-insight >}}

---

**[The Hacker News에서 전체 기사 읽기 ›](https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html)**
