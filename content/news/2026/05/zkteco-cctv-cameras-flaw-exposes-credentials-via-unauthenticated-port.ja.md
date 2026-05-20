---
title: "ZKTeco製CCTVカメラの脆弱性、認証不要のポート経由で認証情報が漏洩"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "ja"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAがZKTeco製CCTVカメラのCVE-2026-8598を警告。文書化されていないポートを介した認証情報の窃取が可能。パッチはファームウェアV5.0.1.2.20260421で提供。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "ZKTeco製CCTVカメラ"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAがZKTeco製CCTVカメラのCVE-2026-8598を警告。文書化されていないポートを介した認証情報の窃取が可能。パッチはファームウェアV5.0.1.2.20260421で提供。

{{< cyber-report severity="Critical" source="CISA" target="ZKTeco製CCTVカメラ" cve="CVE-2026-8598" cvss="9.1" >}}

CISAは、ZKTeco製CCTVカメラにおける重大な認証バイパスの脆弱性に関する勧告（ICSA-26-139-04）を公開しました。CVE-2026-8598として追跡されるこの脆弱性は、認証なしでアクセス可能な文書化されていない設定エクスポートポートに関連しています。悪用に成功すると、カメラアカウントの認証情報の取得を含む情報漏洩につながる可能性があります。

{{< ad-banner >}}

この脆弱性は、ZKTeco SSC335-GC2063-Face-0b77ソリューションファームウェアのV5.0.1.2.20260421より前のバージョンに影響します。CVSS v3基本スコアは9.1で、重大な深刻度を示しています。影響を受けるデバイスは世界中の商業施設に展開されており、ベンダーは中国に本社を置いています。

ZKTecoは、この問題に対処するためにパッチ適用済みのファームウェアバージョンV5.0.1.2.20260421をリリースしました。ユーザーは直ちにアップグレードすることを強く推奨します。この脆弱性はCWE-288（代替パスまたはチャネルを使用した認証バイパス）に分類されています。

{{< netrunner-insight >}}

これは、公開されたデバッグインターフェースがバックドアと化す典型的な例です。SOCアナリストは、ネットワーク上のZKTecoカメラを直ちにスキャンし、ファームウェアバージョンを確認すべきです。DevSecOpsにとっては、IoTファームウェアビルドにおいて文書化されていないポートを無効化またはファイアウォールで保護する必要性を強調しています。V5.0.1.2.20260421未満のファームウェアを搭載したカメラは、証明されるまで侵害されたものとして扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
