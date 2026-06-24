---
title: "Salesforce 공격 확산, Icarus가 Klue 침해를 통해 탈취 데이터 유출"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "ko"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "공격자들이 Klue의 OAuth 토큰을 악용하여 Salesforce 인스턴스에 접근했으며, Icarus가 탈취 데이터를 유출함에 따라 더 많은 피해자가 드러나고 있습니다."
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Klue OAuth 토큰을 통한 Salesforce 인스턴스"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

공격자들이 Klue의 OAuth 토큰을 악용하여 Salesforce 인스턴스에 접근했으며, Icarus가 탈취 데이터를 유출함에 따라 더 많은 피해자가 드러나고 있습니다.

{{< cyber-report severity="High" source="Dark Reading" target="Klue OAuth 토큰을 통한 Salesforce 인스턴스" >}}

Salesforce를 대상으로 한 지속적인 공격의 범위가 확대되면서, Icarus로 추적되는 위협 행위자들이 여러 피해자로부터 탈취한 데이터를 유출하고 있습니다. 공격자들은 처음에 애플리케이션 공급업체 Klue를 침해하고 해당 업체의 OAuth 토큰을 활용하여 고객의 Salesforce 환경에 무단 접근했습니다.

{{< ad-banner >}}

Dark Reading에 따르면, 최초 공개 이후 새로운 피해자들이 나타나 이 공격 캠페인이 이전에 알려진 것보다 더 광범위함을 시사합니다. OAuth 토큰 사용으로 공격자들은 기존 인증 통제를 우회하고 일반적인 경보를 발생시키지 않고 Salesforce 데이터에 직접 접근할 수 있었습니다.

Klue와 같은 타사 공급업체와 Salesforce 통합을 사용하는 조직은 OAuth 토큰 권한을 감사하고 비정상적인 접근 패턴을 모니터링할 것을 권고합니다. Icarus 그룹이 탈취 데이터 유출을 시작함에 따라 영향을 받은 기업들의 대응이 더욱 시급해졌습니다.

{{< netrunner-insight >}}

이번 공격은 SaaS 생태계에서 OAuth 토큰 남용의 위험을 강조합니다. SOC 분석가는 통합된 타사 앱의 비정상적인 API 호출 및 토큰 사용을 모니터링하는 데 우선순위를 두어야 합니다. DevSecOps 팀은 엄격한 토큰 수명 주기 관리를 시행하고 피해 범위를 제한하기 위해 적시 권한을 구현해야 합니다.

{{< /netrunner-insight >}}

---

**[Dark Reading에서 전체 기사 읽기 ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
