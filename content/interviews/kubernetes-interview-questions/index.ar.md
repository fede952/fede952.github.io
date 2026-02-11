---
title: "Kubernetes (K8s) التحضير للمقابلة: أسئلة وأجوبة المستوى المتقدم"
description: "20 سؤالاً متقدماً في Kubernetes لمقابلات DevOps و SRE على المستوى المتقدم. يغطي البنية المعمارية، دورة حياة Pod، الشبكات، التخزين، RBAC واستكشاف أخطاء الإنتاج وإصلاحها."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) التحضير للمقابلة: أسئلة وأجوبة المستوى المتقدم",
    "description": "20 سؤالاً متقدماً في Kubernetes يغطي البنية المعمارية، الشبكات، التخزين، الأمان واستكشاف أخطاء الإنتاج وإصلاحها.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ar"
  }
---

## تهيئة النظام

Kubernetes هو نظام التشغيل للسحابة — والمهارة الأكثر طلباً لأدوار DevOps و SRE وهندسة المنصات. مقابلات المستوى المتقدم تتعمق: ستُسأل عن المكونات الداخلية لمستوى التحكم، نماذج الشبكات، RBAC، إدارة الموارد، وكيفية تصحيح أخطاء حوادث الإنتاج تحت الضغط. يحتوي هذا الدليل على 20 سؤالاً تظهر بشكل متكرر في مقابلات أفضل شركات التقنية، مع إجابات تُظهر العمق المتوقع على مستوى Staff/Senior.

**هل تحتاج إلى مراجعة سريعة للأوامر؟** احتفظ بـ [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/) مفتوحاً أثناء تحضيرك.

---

## البنية المعمارية

<details>
<summary><strong>1. صف مكونات مستوى التحكم في Kubernetes ومسؤولياتها.</strong></summary>
<br>

يدير مستوى التحكم حالة المجموعة:

- **kube-apiserver**: البوابة الأمامية للمجموعة. كل أمر `kubectl`، وعمل وحدة التحكم، وقرار المجدول يمر عبر خادم API. يتحقق من الصحة ويحفظ الحالة في etcd.
- **etcd**: مخزن مفتاح-قيمة موزع يحتفظ بحالة المجموعة بالكامل (الحالة المرغوبة، الحالة الفعلية، التكوينات، الأسرار). هو المصدر الوحيد للحقيقة.
- **kube-scheduler**: يراقب الـ Pods المنشأة حديثاً بدون عقدة مخصصة ويختار عقدة بناءً على متطلبات الموارد، قواعد التقارب، التلويثات والقيود.
- **kube-controller-manager**: يشغل حلقات وحدات التحكم (وحدات تحكم Deployment، ReplicaSet، Node، Job) التي تعمل باستمرار على مطابقة الحالة المرغوبة مع الحالة الفعلية.
- **cloud-controller-manager**: يتكامل مع واجهات برمجة تطبيقات مزود السحابة لموازنات الأحمال، وتوفير التخزين، ودورة حياة العقد.
</details>

<details>
<summary><strong>2. ماذا يحدث عند تنفيذ `kubectl apply -f deployment.yaml`؟</strong></summary>
<br>

1. يرسل `kubectl` طلب HTTP POST/PATCH إلى **خادم API** مع بيان Deployment.
2. يقوم خادم API **بالتحقق** من الطلب (المصادقة، التفويض عبر RBAC، وحدات تحكم القبول).
3. يكتب خادم API كائن Deployment في **etcd**.
4. يكتشف **وحدة تحكم Deployment** الـ Deployment الجديد وينشئ **ReplicaSet**.
5. يكتشفه **وحدة تحكم ReplicaSet** وينشئ العدد المحدد من كائنات **Pod**.
6. يكتشف **المجدول** الـ Pods غير المجدولة ويخصص كلاً منها لعقدة بناءً على توفر الموارد والقيود.
7. يكتشف **kubelet** على كل عقدة مخصصة تعيين Pod، ويسحب صورة الحاوية، ويبدأ الحاوية عبر وقت تشغيل الحاوية (containerd/CRI-O).
8. يقوم **kube-proxy** على كل عقدة بتحديث قواعد iptables/IPVS إذا كان هناك Service مرتبط.
</details>

<details>
<summary><strong>3. ما الفرق بين Deployment و StatefulSet و DaemonSet؟</strong></summary>
<br>

- **Deployment**: يدير التطبيقات عديمة الحالة. الـ Pods قابلة للتبديل، ويمكن توسيعها بحرية، ويتم إنشاؤها/تدميرها بأي ترتيب. الأفضل لخوادم الويب وواجهات API والعمال.
- **StatefulSet**: يدير التطبيقات ذات الحالة. كل Pod يحصل على **اسم مضيف ثابت** (`pod-0`، `pod-1`)، **تخزين دائم** (PVC لكل Pod)، ويتم إنشاء/تدمير الـ Pods **بالترتيب**. الأفضل لقواعد البيانات، Kafka، ZooKeeper.
- **DaemonSet**: يضمن **Pod واحد لكل عقدة**. عندما تنضم عقدة جديدة للمجموعة، يتم جدولة Pod عليها تلقائياً. الأفضل لجامعي السجلات، وكلاء المراقبة، إضافات الشبكة.
</details>

<details>
<summary><strong>4. اشرح دورة حياة Pod ومراحلها.</strong></summary>
<br>

يمر الـ Pod بهذه المراحل:

1. **Pending**: تم قبول Pod ولكن لم تتم جدولته بعد أو يتم سحب الصور.
2. **Running**: حاوية واحدة على الأقل قيد التشغيل أو البدء/إعادة التشغيل.
3. **Succeeded**: جميع الحاويات خرجت بالرمز 0 (لأحمال عمل Jobs/الدفعات).
4. **Failed**: جميع الحاويات انتهت، واحدة على الأقل خرجت برمز غير صفري.
5. **Unknown**: العقدة غير قابلة للوصول، لا يمكن تحديد حالة Pod.

داخل Pod قيد التشغيل، يمكن أن تكون الحاويات في حالات: **Waiting** (سحب صورة، حاويات init)، **Running**، أو **Terminated** (خرجت أو تعطلت).
</details>

## الشبكات

<details>
<summary><strong>5. اشرح نموذج شبكات Kubernetes.</strong></summary>
<br>

تتبع شبكات Kubernetes ثلاث قواعد أساسية:

1. **كل Pod يحصل على عنوان IP خاص به** — لا NAT بين الـ Pods.
2. **جميع الـ Pods يمكنها التواصل مع جميع الـ Pods الأخرى** عبر العقد بدون NAT.
3. **عنوان IP الذي يراه Pod لنفسه** هو نفس عنوان IP الذي يستخدمه الآخرون للوصول إليه.

يتم تنفيذ هذا بواسطة إضافات CNI (واجهة شبكة الحاوية) مثل Calico، Flannel، Cilium أو Weave. تنشئ شبكة overlay أو underlay تستوفي هذه القواعد. كل عقدة تحصل على شبكة فرعية Pod CIDR، وتتعامل إضافة CNI مع التوجيه بين العقد.
</details>

<details>
<summary><strong>6. ما الفرق بين خدمات ClusterIP و NodePort و LoadBalancer؟</strong></summary>
<br>

- **ClusterIP** (الافتراضي): عنوان IP افتراضي داخلي فقط. يمكن الوصول إليه فقط من داخل المجموعة. يُستخدم للتواصل بين الخدمات.
- **NodePort**: يكشف الخدمة على منفذ ثابت (30000-32767) على عنوان IP لكل عقدة. يمكن للحركة الخارجية الوصول إلى `<NodeIP>:<NodePort>`. يُبنى فوق ClusterIP.
- **LoadBalancer**: يوفر موازن أحمال خارجي عبر مزود السحابة. يحصل على عنوان IP/DNS عام. يُبنى فوق NodePort. يُستخدم للخدمات العامة في الإنتاج.

هناك أيضاً **ExternalName**، الذي يربط خدمة بسجل DNS CNAME (بدون وكالة، فقط حل DNS).
</details>

<details>
<summary><strong>7. ما هو Ingress وكيف يختلف عن Service؟</strong></summary>
<br>

يعمل **Service** على الطبقة 4 (TCP/UDP) — يوجه الحركة إلى الـ Pods بناءً على عنوان IP والمنفذ.

يعمل **Ingress** على الطبقة 7 (HTTP/HTTPS) — يوجه الحركة بناءً على اسم المضيف ومسار URL. يمكن لـ Ingress واحد توجيه `api.example.com` إلى خدمة API و `app.example.com` إلى خدمة الواجهة الأمامية، كل ذلك من خلال موازن أحمال واحد.

يتطلب Ingress **وحدة تحكم Ingress** (nginx-ingress، Traefik، HAProxy، AWS ALB) لتنفيذ قواعد التوجيه فعلياً. مورد Ingress هو مجرد تكوين — وحدة التحكم تقوم بالعمل.
</details>

<details>
<summary><strong>8. كيف يعمل DNS داخل مجموعة Kubernetes؟</strong></summary>
<br>

يشغل Kubernetes **CoreDNS** (أو kube-dns) كإضافة للمجموعة. كل خدمة تحصل على سجل DNS:

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

عندما يقوم Pod بإجراء استعلام DNS لـ `my-service`، يضيف المحلل في `/etc/resolv.conf` (المكوّن بواسطة kubelet) نطاقات البحث ويستعلم CoreDNS. يراقب CoreDNS خادم API لتغييرات Service/Endpoint ويحدث سجلاته تلقائياً.
</details>

## التخزين

<details>
<summary><strong>9. اشرح PersistentVolume (PV) و PersistentVolumeClaim (PVC) و StorageClass.</strong></summary>
<br>

- **PersistentVolume (PV)**: قطعة تخزين يوفرها المسؤول أو ديناميكياً بواسطة StorageClass. توجد بشكل مستقل عن أي Pod. لها دورة حياة منفصلة عن الـ Pods.
- **PersistentVolumeClaim (PVC)**: طلب تخزين من Pod. يحدد الحجم، وضع الوصول واختيارياً StorageClass. يربط Kubernetes الـ PVC بـ PV مطابق.
- **StorageClass**: يحدد فئة تخزين (SSD، HDD، NFS) والموفر الذي ينشئ PVs ديناميكياً. يتيح توفير التخزين عند الطلب — لا حاجة لتدخل المسؤول.

التدفق: Pod يشير إلى PVC → PVC يطلب تخزيناً من StorageClass → StorageClass يُشغّل الموفر → الموفر ينشئ PV → PVC يرتبط بـ PV → Pod يُركّب PV.
</details>

<details>
<summary><strong>10. ما هي أوضاع الوصول وسياسات الاسترداد؟</strong></summary>
<br>

**أوضاع الوصول**:
- **ReadWriteOnce (RWO)**: تركيب للقراءة/الكتابة بواسطة عقدة واحدة. الأكثر شيوعاً (AWS EBS، GCE PD).
- **ReadOnlyMany (ROX)**: تركيب للقراءة فقط بواسطة عقد متعددة. يُستخدم للتكوينات المشتركة.
- **ReadWriteMany (RWX)**: تركيب للقراءة/الكتابة بواسطة عقد متعددة. يتطلب تخزين شبكي (NFS، EFS، CephFS).

**سياسات الاسترداد** (ما يحدث عند حذف PVC):
- **Retain**: يتم الاحتفاظ بـ PV مع بياناته. يجب على المسؤول استرداده يدوياً.
- **Delete**: يتم حذف PV والتخزين الأساسي. الافتراضي للتوفير الديناميكي.
- **Recycle** (مهمل): `rm -rf` أساسي على المجلد. استخدم Retain أو Delete بدلاً من ذلك.
</details>

## الأمان و RBAC

<details>
<summary><strong>11. كيف يعمل RBAC في Kubernetes؟</strong></summary>
<br>

RBAC (التحكم في الوصول المبني على الأدوار) له أربعة كائنات:

- **Role**: يحدد الصلاحيات (الأفعال: get، list، create، delete) على الموارد (pods، services، secrets) داخل **مساحة اسم واحدة**.
- **ClusterRole**: نفس Role ولكن على **مستوى المجموعة** (جميع مساحات الأسماء، أو الموارد على مستوى المجموعة مثل العقد).
- **RoleBinding**: يربط Role بمستخدم أو مجموعة أو حساب خدمة داخل مساحة اسم.
- **ClusterRoleBinding**: يربط ClusterRole بموضوع عبر المجموعة بأكملها.

المبدأ: ابدأ بأقل الصلاحيات اللازمة. لا تربط أبداً `cluster-admin` بحسابات خدمة التطبيقات. راجع RBAC بانتظام باستخدام `kubectl auth can-i`.
</details>

<details>
<summary><strong>12. ما هي معايير أمان Pod (PSS)؟</strong></summary>
<br>

حلت معايير أمان Pod محل PodSecurityPolicies (أُزيلت في K8s 1.25). تحدد ثلاثة مستويات أمان:

- **Privileged**: بدون قيود. يسمح بكل شيء. يُستخدم للـ Pods على مستوى النظام (إضافات CNI، برامج تشغيل التخزين).
- **Baseline**: يمنع تصعيد الامتيازات المعروفة. يحجب hostNetwork، hostPID، الحاويات المميزة، لكن يسمح بمعظم أحمال العمل.
- **Restricted**: أقصى أمان. يتطلب non-root، إسقاط جميع القدرات، نظام ملفات جذر للقراءة فقط، عدم تصعيد الامتيازات.

يُنفذ عبر وحدة تحكم **Pod Security Admission** على مستوى مساحة الاسم باستخدام التسميات:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. كيف تدير الأسرار في Kubernetes بشكل آمن؟</strong></summary>
<br>

أسرار Kubernetes الافتراضية **مشفرة بـ base64، وليست مشفرة**. أي شخص لديه وصول API يمكنه فك ترميزها.

خطوات التقوية:
1. **تمكين التشفير في حالة السكون** في etcd (`EncryptionConfiguration` مع AES-CBC أو مزود KMS).
2. **استخدام مديري أسرار خارجيين** (Vault، AWS Secrets Manager) مع External Secrets Operator أو CSI Secrets Store Driver.
3. **RBAC**: تقييد `get`/`list` على الأسرار فقط لحسابات الخدمة التي تحتاجها.
4. **تركيب كملفات**، وليس متغيرات بيئة — متغيرات البيئة يمكن أن تتسرب عبر السجلات، تفريغات الأعطال و `/proc`.
5. **تدوير الأسرار** بانتظام واستخدام بيانات اعتماد قصيرة العمر حيثما أمكن.
</details>

## الجدولة والموارد

<details>
<summary><strong>14. اشرح طلبات الموارد والحدود.</strong></summary>
<br>

- **الطلبات (Requests)**: كمية CPU/الذاكرة **المضمونة** للحاوية. يستخدم المجدول الطلبات لتحديد أي عقدة لديها سعة كافية.
- **الحدود (Limits)**: **الحد الأقصى** الذي يمكن للحاوية استخدامه. إذا تجاوزت الحاوية حد الذاكرة، يتم قتلها بسبب OOM. إذا تجاوزت حد CPU، يتم تقييدها.

فئات QoS بناءً على الطلبات/الحدود:
- **Guaranteed**: الطلبات == الحدود لجميع الحاويات. أعلى أولوية، آخر من يتم إخلاؤه.
- **Burstable**: الطلبات < الحدود. أولوية متوسطة.
- **BestEffort**: لا طلبات أو حدود محددة. أول من يتم إخلاؤه تحت الضغط.

أفضل ممارسة: حدد دائماً الطلبات (لدقة الجدولة) والحدود (لاستقرار المجموعة).
</details>

<details>
<summary><strong>15. ما هي التلويثات (taints) والتسامحات (tolerations) وتقارب العقدة (node affinity)؟</strong></summary>
<br>

- **التلويثات (Taints)** تُطبق على العقد: "لا تجدول Pods هنا ما لم تتسامح مع هذا التلويث." مثال: `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **التسامحات (Tolerations)** تُطبق على الـ Pods: "يمكنني تحمل هذا التلويث." الـ Pods ذات التسامحات المطابقة يمكن جدولتها على العقد الملوثة.
- **تقارب العقدة (Node Affinity)** هو مواصفة Pod تقول "فضّل أو اشترط الجدولة على عقد بتسميات محددة." مثال: اشتراط عقد بـ `disktype=ssd`.

استخدمها معاً: لوّث عقد GPU → فقط الـ Pods ذات تسامحات GPU وتقارب GPU تصل إلى هناك. يمنع أحمال العمل غير GPU من إهدار أجهزة باهظة الثمن.
</details>

## استكشاف الأخطاء وإصلاحها

<details>
<summary><strong>16. Pod عالق في CrashLoopBackOff. كيف تقوم بتصحيحه؟</strong></summary>
<br>

`CrashLoopBackOff` يعني أن الحاوية تستمر في التعطل و Kubernetes ينتظر قبل إعادة تشغيلها (تأخير أسي حتى 5 دقائق).

خطوات التصحيح:
1. `kubectl describe pod <name>` — تحقق من Events، Last State، Exit Code.
2. `kubectl logs <pod> --previous` — اقرأ سجلات المثيل المتعطل.
3. تحليل رمز الخروج: 1 = خطأ تطبيق، 137 = قتل OOM، 139 = segfault، 143 = SIGTERM.
4. إذا تعطلت الحاوية بسرعة كبيرة للسجلات: `kubectl run debug --image=<image> --command -- sleep 3600` وادخل بـ exec لفحص البيئة.
5. تحقق مما إذا كانت فحوصات readiness/liveness مكونة بشكل خاطئ (فحص يصل إلى منفذ/مسار خاطئ).
6. تحقق من حدود الموارد — قد يتم قتل الحاوية بسبب OOM قبل أن تتمكن من تسجيل أي شيء.
</details>

<details>
<summary><strong>17. Service لا يوجه الحركة إلى الـ Pods. ماذا تتحقق؟</strong></summary>
<br>

1. **تطابق التسميات**: يجب أن يتطابق `spec.selector` للـ Service مع `metadata.labels` للـ Pod تماماً.
2. **وجود Endpoints**: `kubectl get endpoints <service>` — إذا كان فارغاً، المحدد لا يتطابق مع أي Pods قيد التشغيل.
3. **الـ Pods جاهزة**: فقط الـ Pods التي تجتاز فحوصات readiness تظهر في Endpoints. تحقق من `kubectl get pods` لحالة Ready.
4. **عدم تطابق المنافذ**: يجب أن يتطابق `targetPort` للـ Service مع المنفذ الذي تستمع عليه الحاوية فعلياً.
5. **سياسة الشبكة**: قد تحجب NetworkPolicy الدخول إلى الـ Pods.
6. **DNS**: من Pod تصحيح، `nslookup <service-name>` للتحقق من أن حل DNS يعمل.
</details>

<details>
<summary><strong>18. كيف تنفذ نشراً بدون توقف؟</strong></summary>
<br>

1. **استراتيجية التحديث المتدرج** (الافتراضية): اضبط `maxUnavailable: 0` و `maxSurge: 1` لضمان إزالة الـ Pods القديمة فقط بعد أن تكون الـ Pods الجديدة جاهزة.
2. **فحوصات الجاهزية**: بدون فحص readiness، يعتبر Kubernetes الـ Pod جاهزاً فوراً بعد البدء — الحركة تصله قبل تهيئة التطبيق.
3. **خطاف PreStop**: أضف خطاف دورة حياة `preStop` مع سكون قصير (5-10 ثوانٍ) للسماح بإكمال الطلبات الجارية قبل إزالة Pod من نقاط نهاية Service.
4. **PodDisruptionBudget (PDB)**: يضمن أن عدداً أدنى من الـ Pods متاح دائماً أثناء الاضطرابات الطوعية (تصريف العقد، الترقيات).
5. **الإيقاف الرشيق**: يجب أن يتعامل التطبيق مع SIGTERM وينهي الطلبات النشطة قبل الخروج.
</details>

<details>
<summary><strong>19. ما هو Horizontal Pod Autoscaler وكيف يعمل؟</strong></summary>
<br>

يقوم HPA تلقائياً بتوسيع عدد نسخ Pod بناءً على المقاييس المرصودة (CPU، الذاكرة أو مقاييس مخصصة).

كيف يعمل:
1. يستعلم HPA من **Metrics Server** (أو واجهة برمجة المقاييس المخصصة) كل 15 ثانية.
2. يحسب: `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. إذا اختلفت النسخ المرغوبة عن الحالية، يحدث عدد نسخ Deployment.
4. فترات التبريد تمنع التذبذب: استقرار التوسيع (الافتراضي 0 ثانية)، استقرار التقليص (الافتراضي 300 ثانية).

المتطلبات: تثبيت Metrics Server، تحديد طلبات الموارد على الحاويات (لمقاييس CPU/الذاكرة)، تكوين حدود النسخ الدنيا/القصوى.
</details>

<details>
<summary><strong>20. ما الفرق بين فحص liveness وفحص readiness؟</strong></summary>
<br>

- **فحص Liveness**: "هل الحاوية حية؟" إذا فشل، يقوم kubelet **بقتل وإعادة تشغيل** الحاوية. يُستخدم لاكتشاف حالات الجمود أو العمليات المجمدة.
- **فحص Readiness**: "هل الحاوية جاهزة لخدمة الحركة؟" إذا فشل، يتم **إزالة Pod من نقاط نهاية Service** (لا يتم توجيه حركة إليه)، لكن الحاوية لا يُعاد تشغيلها. يُستخدم لفترات الإحماء، فحوصات التبعيات، الحمل الزائد المؤقت.

هناك أيضاً **فحص Startup**: يعطل فحوصات liveness/readiness حتى يبدأ التطبيق. مفيد للتطبيقات بطيئة البدء لمنع القتل المبكر.

خطأ شائع: استخدام فحص liveness يتحقق من تبعية downstream (قاعدة بيانات). إذا تعطلت قاعدة البيانات، تعيد جميع الـ Pods التشغيل — مما يزيد الانقطاع سوءاً. يجب أن يتحقق Liveness من التطبيق نفسه فقط.
</details>
