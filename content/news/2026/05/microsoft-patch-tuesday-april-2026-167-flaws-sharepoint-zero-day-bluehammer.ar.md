---
title: "تحديثات الثلاثاء من مايكروسوفت أبريل 2026: 167 ثغرة، ثغرة يوم الصفر في SharePoint، وBlueHammer"
date: "2026-05-11T10:37:48Z"
original_date: "2026-04-14T21:47:59"
lang: "ar"
translationKey: "microsoft-patch-tuesday-april-2026-167-flaws-sharepoint-zero-day-bluehammer"
author: "NewsBot (Validated by Federico Sella)"
description: "مايكروسوفت تصلح 167 ثغرة أمنية بما في ذلك ثغرة يوم الصفر في SharePoint وثغرة معلنة علنًا في Windows Defender (BlueHammer). جوجل كروم وأدوبي ريدر أيضًا يصححان ثغرات تم استغلالها بنشاط."
original_url: "https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/"
source: "Krebs on Security"
severity: "Critical"
target: "Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

مايكروسوفت تصلح 167 ثغرة أمنية بما في ذلك ثغرة يوم الصفر في SharePoint وثغرة معلنة علنًا في Windows Defender (BlueHammer). جوجل كروم وأدوبي ريدر أيضًا يصححان ثغرات تم استغلالها بنشاط.

{{< cyber-report severity="Critical" source="Krebs on Security" target="Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader" >}}

تحديثات الثلاثاء من مايكروسوفت لشهر أبريل 2026 تعالج عددًا هائلاً يبلغ 167 ثغرة أمنية عبر Windows والبرامج ذات الصلة. من بين الأكثر خطورة ثغرة يوم الصفر في SharePoint Server التي قد تسمح بتنفيذ تعليمات برمجية عن بُعد، على الرغم من عدم تقديم معرف CVE في التقرير. بالإضافة إلى ذلك، تم إصلاح ضعف معلن علنًا في Windows Defender، يُعرف باسم 'BlueHammer'.

{{< ad-banner >}}

بشكل منفصل، قام جوجل كروم بتصحيح ثغرة يوم الصفر الرابعة له في عام 2026، مما يواصل اتجاه التحديثات المتكررة للمتصفح. كما تلقى أدوبي ريدر تحديثًا طارئًا لمعالجة ثغرة تم استغلالها بنشاط يمكن أن تؤدي إلى تنفيذ تعليمات برمجية عن بُعد. يجب على المؤسسات إعطاء الأولوية لهذه التحديثات نظرًا للاستغلال النشط.

الحجم الهائل للتصحيحات هذا الشهر يؤكد أهمية عمليات إدارة التصحيحات القوية. يجب على فرق الأمن التركيز على ثغرة يوم الصفر في SharePoint ومشكلة Windows Defender كأولويات فورية، مع ضمان تحديث كروم وأدوبي ريدر عبر المؤسسة.

{{< netrunner-insight >}}

لمحللي SOC، أعط الأولوية لثغرة يوم الصفر في SharePoint وثغرة BlueHammer في Windows Defender للتصحيح الفوري، حيث أنهما إما تم استغلالهما بنشاط أو معروفتان علنًا. يجب على فرق DevSecOps دمج هذه التحديثات في خطوط CI/CD الخاصة بهم والتحقق من أن أدوات حماية نقطة النهاية لم تتأثر بإصلاح Defender. تصحيحات كروم وأدوبي ريدر تستحق أيضًا اهتمامًا عاجلاً نظرًا لحالة استغلالها النشط.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على Krebs on Security ›](https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/)**
