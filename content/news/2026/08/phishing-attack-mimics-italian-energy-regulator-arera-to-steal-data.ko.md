---
title: "피싱 공격, 이탈리아 에너지 규제기관 ARERA 사칭해 데이터 탈취"
date: "2026-08-17T07:49:27Z"
original_date: "2026-08-05T13:20:37"
lang: "ko"
translationKey: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
slug: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID는 ARERA를 사칭하는 사기 사이트를 경고하며, 수도 사회 보너스를 미끼로 오타 도메인(typosquatting)을 이용해 개인 및 금융 정보를 수집한다고 밝혔습니다."
original_url: "https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/"
source: "CERT-AgID"
severity: "Medium"
target: "이탈리아 시민 및 ARERA 사용자"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID는 ARERA를 사칭하는 사기 사이트를 경고하며, 수도 사회 보너스를 미끼로 오타 도메인(typosquatting)을 이용해 개인 및 금융 정보를 수집한다고 밝혔습니다.

{{< cyber-report severity="Medium" source="CERT-AgID" target="이탈리아 시민 및 ARERA 사용자" >}}

CERT-AGID는 이탈리아 에너지·네트워크·환경 규제기관인 ARERA의 이름과 로고를 모방한 사기 웹사이트를 식별했습니다. 이 사이트는 경제적 또는 신체적 어려움을 겪는 가구의 수도 공급 비용을 줄이기 위한 합법적인 제도인 '수도 사회 보너스'와 관련된 환급을 약속하며 피해자를 유인합니다.

{{< ad-banner >}}

이 피싱 캠페인은 오타 도메인(typosquatting) 기술을 사용하여 가짜 도메인의 신뢰성을 높여 정식 ARERA 웹사이트와 거의 동일하게 보이게 만듭니다. 목표는 사용자가 개인 및 금융 정보를 공개하도록 속여 신원 도용이나 금융 사기에 악용하는 것입니다.

이번 사건은 잘 알려진 정부 또는 규제 기관을 악용하는 피싱 캠페인의 지속적인 위협을 강조합니다. 사용자는 환급이나 보너스를 제공한다는 통신의 진위를 확인하고, 원치 않는 이메일이나 메시지의 링크를 클릭하지 않도록 주의해야 합니다.

{{< netrunner-insight >}}

SOC 분석가에게 이 캠페인은 중요한 공공 서비스와 관련된 오타 도메인을 모니터링해야 할 필요성을 강조합니다. DNS 필터링을 구현하고 공식 채널 확인에 대한 사용자 교육을 통해 이러한 위협을 완화할 수 있습니다. DevSecOps 팀은 유사 도메인을 추적하는 위협 인텔리전스 피드를 통합하여 사전에 액세스를 차단하는 것을 고려해야 합니다.

{{< /netrunner-insight >}}

---

**[CERT-AgID에서 전체 기사 읽기 ›](https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/)**
