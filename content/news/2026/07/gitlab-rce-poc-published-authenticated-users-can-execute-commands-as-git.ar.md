---
title: "نشر استغلال RCE لـ GitLab: المستخدمون الموثوقون يمكنهم تنفيذ أوامر كمستخدم Git"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "ar"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "تم نشر استغلال إثبات المفهوم لثغرة تنفيذ التعليمات البرمجية عن بعد في GitLab، يستهدف خوادم الإدارة الذاتية 18.11.3 غير المصححة. يمكن للمستخدمين الموثوقين تشغيل الأوامر كمستخدم git."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab self-managed 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تم نشر استغلال إثبات المفهوم لثغرة تنفيذ التعليمات البرمجية عن بعد في GitLab، يستهدف خوادم الإدارة الذاتية 18.11.3 غير المصححة. يمكن للمستخدمين الموثوقين تشغيل الأوامر كمستخدم git.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab self-managed 18.11.3" >}}

في 24 يوليو 2026، نشر باحثو الأمن في depthfirst استغلال إثبات المفهوم لثغرة تنفيذ التعليمات البرمجية عن بعد في GitLab. الثغرة، التي قامت GitLab بتصحيحها في 10 يونيو 2026، تسمح لأي مستخدم موثوق لديه صلاحيات الدفع إلى مشروع بتنفيذ أوامر عشوائية كمستخدم git على خوادم GitLab ذات الإدارة الذاتية 18.11.3 التي لم تطبق التحديث.

{{< ad-banner >}}

يستغل الاستغلال دفتر Jupyter معدل تم إرساله إلى مشروع. عندما يفتح المهاجم فرق الالتزام، يقوم الدفتر الخبيث بتشغيل تسرب في الذاكرة، مما يتيح تنفيذ الأوامر. هذه التقنية تتجاوز ضوابط المصادقة النموذجية ولا تتطلب صلاحيات خاصة تتجاوز الوصول القياسي للمشروع.

يجب على المؤسسات التي تدير مثيلات GitLab ذات الإدارة الذاتية التحقق فورًا من تطبيق تصحيح 10 يونيو. التوفر العام لرمز الاستغلال يزيد من خطر الاستغلال النشط، خاصة للمثيلات المعرضة للإنترنت. يجب على الفرق الزرقاء مراقبة التزامات دفاتر Jupyter غير المعتادة ونشاط مستخدم git غير المتوقع.

{{< netrunner-insight >}}

يؤكد هذا الاستغلال على خطر تأخير التصحيح في منصات CI/CD ذات الإدارة الذاتية. يجب على محللي SOC إعطاء الأولوية للكشف عن عمليات مستخدم git الشاذة ورفع دفاتر Jupyter غير المتوقعة. يجب على فرق DevSecOps فرض نافذة تصحيح صارمة لـ GitLab والنظر في تقسيم الشبكة للحد من تعرض المثيلات ذات الإدارة الذاتية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
