---
title: "بوت نت NadMesh يستهدف خدمات الذكاء الاصطناعي المكشوفة لسرقة بيانات الاعتماد السحابية"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "ar"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "بوت نت جديد مبني على لغة Go، يُدعى NadMesh، يصطاد منصات الذكاء الاصطناعي المكشوفة مثل ComfyUI وOllama، ويسرق مفاتيح AWS ورموز Kubernetes. يُزعم سرقة أكثر من 3,800 مفتاح."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "خدمات الذكاء الاصطناعي المكشوفة (ComfyUI, Ollama, n8n، وغيرها)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

بوت نت جديد مبني على لغة Go، يُدعى NadMesh، يصطاد منصات الذكاء الاصطناعي المكشوفة مثل ComfyUI وOllama، ويسرق مفاتيح AWS ورموز Kubernetes. يُزعم سرقة أكثر من 3,800 مفتاح.

{{< cyber-report severity="High" source="The Hacker News" target="خدمات الذكاء الاصطناعي المكشوفة (ComfyUI, Ollama, n8n، وغيرها)" >}}

ظهر بوت نت جديد يُدعى NadMesh، مكتوب بلغة Go، في أوائل يوليو 2026، مستهدفًا خدمات الذكاء الاصطناعي المكشوفة لسرقة بيانات الاعتماد السحابية ورموز Kubernetes. يُظهر لوحة تحكم مشغل البوت نت 3,811 مفتاح AWS فريدًا تم جمعه، مما يشير إلى نطاق تشغيلي كبير. يستخدم NadMesh أداة حصاد تعتمد على Shodan لملء قائمة المسح الضوئي باستمرار بنسخ ضعيفة من أدوات الذكاء الاصطناعي الشائعة مثل ComfyUI وOllama وn8n وOpen WebUI وLangflow وGradio.

{{< ad-banner >}}

غالبًا ما يتم نشر منصات الذكاء الاصطناعي هذه بسرعة من قبل فرق التطوير دون تعزيز أمني مناسب، مما يتركها مكشوفة على الإنترنت. يستغل البوت نت هذا الافتقار إلى حماية جدار الحماية للوصول واستخراج بيانات الاعتماد الحساسة. يشير التركيز على خدمات الذكاء الاصطناعي إلى تحول في استهداف المهاجمين نحو البنية التحتية السحابية عالية القيمة وخطوط أنابيب التعلم الآلي.

يجب على المؤسسات التي تشغل أدوات الذكاء الاصطناعي هذه مراجعة تعرضها فورًا، وتقييد الوصول إلى الشبكة، وتدوير أي بيانات اعتماد قد تكون تعرضت للاختراق. يُظهر بوت نت NadMesh مشهد التهديدات المتزايد حيث تصبح خدمات الذكاء الاصطناعي غير المهيأة بشكل صحيح أهدافًا رئيسية لسرقة بيانات الاعتماد والحركة الجانبية.

{{< netrunner-insight >}}

لمحللي SOC: أعط الأولوية لفحص خدمات ComfyUI وOllama وخدمات الذكاء الاصطناعي المماثلة المكشوفة في بيئتك. يجب على فرق DevSecOps فرض تقسيم الشبكة وقواعد جدار الحماية قبل نشر هذه الأدوات. يُعد بوت نت NadMesh تذكيرًا واضحًا بأن النشر السريع دون مراجعة أمنية يدعو إلى سرقة بيانات الاعتماد الآلية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
