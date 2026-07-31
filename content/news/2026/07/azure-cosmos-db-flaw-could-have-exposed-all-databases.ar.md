---
title: "ثغرة في Azure Cosmos DB قد تكشف جميع قواعد البيانات"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "ar"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرة تم إصلاحها في Azure Cosmos DB سمحت بالهروب من بيئة العزل والوصول إلى قواعد البيانات عبر المستأجرين، اكتشفتها Wiz تحت اسم CosmosEscape."
original_url: "https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html"
source: "The Hacker News"
severity: "High"
target: "Azure Cosmos DB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرة تم إصلاحها في Azure Cosmos DB سمحت بالهروب من بيئة العزل والوصول إلى قواعد البيانات عبر المستأجرين، اكتشفتها Wiz تحت اسم CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

كانت ثغرة تم إصلاحها الآن في Azure Cosmos DB يمكن أن تسمح للمهاجم بالهروب من بيئة عزل استعلامات Gremlin والحصول على وصول كامل للقراءة والكتابة إلى قواعد البيانات عبر مستأجري العملاء. تم اكتشاف الثغرة من قبل شركة الأمن Wiz، التي أطلقت على سلسلة الاستغلال اسم 'CosmosEscape'.

{{< ad-banner >}}

بدأت سلسلة الهجوم باستعلام مصمم ضد قاعدة بيانات Gremlin يتحكم فيها المهاجم. ومن هناك، يمكن للمهاجم تحقيق تنفيذ التعليمات البرمجية على البنية التحتية الأساسية، مما قد يعرض العزل بين المستأجرين للخطر.

على الرغم من أن Microsoft قامت بإصلاح المشكلة منذ ذلك الحين، إلا أن الحادث يؤكد الأهمية الحاسمة لعزل المستأجرين في خدمات قواعد البيانات السحابية. يجب على المؤسسات التي تستخدم Azure Cosmos DB مراجعة تكوينات الأمان الخاصة بها ومراقبة أي نشاط غير عادي.

{{< netrunner-insight >}}

بالنسبة لمحللي SOC، يسلط هذا الضوء على الحاجة إلى مراقبة استعلامات Gremlin الشاذة وأنماط الوصول غير المعتادة إلى قواعد البيانات. يجب على فرق DevSecOps التأكد من أن خدمات قواعد البيانات السحابية مهيأة وفق مبدأ الامتياز الأقل وأن آليات العزل يتم تدقيقها بانتظام. على الرغم من إصلاح هذه الثغرة، قد توجد ثغرات مماثلة في خدمات مُدارة أخرى، لذا فإن الصيد الاستباقي للتهديدات أمر ضروري.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
