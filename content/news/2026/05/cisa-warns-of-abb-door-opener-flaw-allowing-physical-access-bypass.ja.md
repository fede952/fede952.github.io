---
title: "CISA、ABB製ドアオープナーの脆弱性により物理アクセスバイパスの可能性を警告"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA勧告ICSA-26-148-04は、ABB Busch-Welcome 2 Wire Door Opener Actuatorにおける認証バイパスの脆弱性（CVE-2025-7705）を詳述しており、不正な建物アクセスを可能にします。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "ABB Busch-Welcome 2 Wire Door Opener Actuator"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA勧告ICSA-26-148-04は、ABB Busch-Welcome 2 Wire Door Opener Actuatorにおける認証バイパスの脆弱性（CVE-2025-7705）を詳述しており、不正な建物アクセスを可能にします。

{{< cyber-report severity="Medium" source="CISA" target="ABB Busch-Welcome 2 Wire Door Opener Actuator" cve="CVE-2025-7705" cvss="6.8" >}}

CISAは、ABB Busch-Welcome 2 Wire Door Opener Actuatorにおける認証バイパスの脆弱性（CVE-2025-7705）に関する勧告ICSA-26-148-04を公開しました。この欠陥は、デフォルトで有効になっている互換モードに起因し、攻撃者が影響を受ける製品が設置された建物に物理的に不正アクセスすることを可能にします。この脆弱性は、Switch Actuator 4 DUおよびSwitch actuator, door/light 4 DUの全バージョンに影響します。

{{< ad-banner >}}

この脆弱性のCVSS v3基本スコアは6.8で、中程度の深刻度を示しています。ABBは、製品のモードスイッチを切り替え、システムを再調整するために電源リセットを実行するという是正手順を提供しています。この製品は世界中、主に商業施設に展開されており、ベンダーはスイスに本社を置いています。

影響を受けるABB Busch-Welcomeシステムを使用している組織は、推奨される緩和策を直ちに適用する必要があります。物理的なセキュリティへの影響を考慮すると、この脆弱性は建物のアクセス制御に重大なリスクをもたらします。セキュリティチームは、再調整手順が正しく実行されていることを確認し、悪用の兆候を監視する必要があります。

{{< netrunner-insight >}}

この脆弱性は、IoTやビルオートメーションデバイスがしばしば安全でないデフォルト設定で出荷されることを痛感させるものです。SOCアナリストは、ABB Busch-Welcomeシステムの資産発見を優先し、手動による再調整が適用されていることを確認すべきです。DevSecOpsチームは、特に物理アクセスを制御するデバイスにおいて、セキュアバイデザインの原則を提唱する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
