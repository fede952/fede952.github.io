---
title: "إصلاح: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "حل خطأ 'Cannot connect to the Docker daemon' في ثوانٍ. تعرّف على ما إذا كانت المشكلة في الخدمة أو في الأذونات، وأصلحها نهائياً."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "إصلاح: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "إصلاح خطوة بخطوة لخطأ اتصال Docker daemon على Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ar"
  }
---

## الخطأ

تقوم بتشغيل أمر Docker فتظهر لك هذه الرسالة:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

أو نسخة أخرى:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

هذا أحد أكثر أخطاء Docker شيوعاً على Linux. يعني أن الطرفية (shell) الخاصة بك لا تستطيع التواصل مع محرك Docker. السبب دائماً واحد من اثنين: خدمة Docker ليست قيد التشغيل، أو أن المستخدم الخاص بك ليس لديه إذن للوصول إلى مقبس Docker.

---

## الإصلاح السريع

### 1. تشغيل خدمة Docker

قد يكون البرنامج الخفي (daemon) ببساطة غير قيد التشغيل. قم بتشغيله:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

إذا أظهر `status` القيمة `active (running)`، فالخدمة تعمل. جرّب أمر Docker مرة أخرى.

### 2. إصلاح أذونات المستخدم

إذا كانت الخدمة تعمل لكنك لا تزال تحصل على "permission denied"، فإن المستخدم الخاص بك ليس في مجموعة `docker`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

بعد ذلك، يجب أن تتمكن من تشغيل `docker ps` بدون `sudo`.

---

## الشرح

يستخدم Docker مقبس Unix (`/var/run/docker.sock`) للتواصل بين عميل CLI والبرنامج الخفي لـ Docker (الخدمة التي تعمل في الخلفية). يجب أن يتحقق شرطان لكي يعمل هذا:

**1. يجب أن يكون البرنامج الخفي لـ Docker قيد التشغيل.** خدمة systemd المسماة `docker.service` تدير البرنامج الخفي. إذا تم تشغيل الجهاز للتو ولم يكن Docker مُفعّلاً عند بدء التشغيل، أو إذا تعطلت الخدمة، فإن ملف المقبس إما غير موجود أو لا يقبل الاتصالات.

**2. يجب أن يكون لدى المستخدم حق الوصول إلى المقبس.** افتراضياً، مقبس Docker مملوك لـ `root:docker` بأذونات `srw-rw----`. هذا يعني أن root وأعضاء مجموعة `docker` فقط يمكنهم القراءة/الكتابة إليه. إذا لم يكن المستخدم في مجموعة `docker`، فإن كل أمر يتطلب `sudo`.

### كيف تحدد المشكلة؟

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

إذا أرجع `systemctl is-active` القيمة `inactive` → فهي **مشكلة في الخدمة** (الإصلاح #1).
إذا كانت الخدمة `active` لكنك تحصل على permission denied → فهي **مشكلة في الأذونات** (الإصلاح #2).

---

## الأخطاء الشائعة

- **Docker المُثبّت عبر Snap**: إذا قمت بتثبيت Docker عبر Snap بدلاً من المستودع الرسمي، فقد يختلف مسار المقبس واسم الخدمة. قم بإلغاء تثبيت نسخة Snap واستخدم حزم Docker CE الرسمية.
- **WSL2 على Windows**: لا يعمل البرنامج الخفي لـ Docker بشكل أصلي في WSL2. تحتاج إلى تشغيل Docker Desktop لنظام Windows، أو يجب عليك تثبيت وتشغيل البرنامج الخفي داخل توزيعة WSL2 يدوياً.
- **Docker Desktop على Mac/Linux**: إذا كنت تستخدم Docker Desktop، فإن البرنامج الخفي يُدار بواسطة تطبيق Desktop وليس systemd. تأكد من أن Docker Desktop مفتوح وقيد التشغيل.

---

## موارد ذات صلة

امنع حدوث هذا الخطأ مرة أخرى. احفظ في المفضلة [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) الكامل الخاص بنا — يغطي أذونات المستخدم وإدارة الخدمات وكل أمر `docker` تحتاجه في بيئة الإنتاج.

هل تحتاج إلى إدارة خدمات ومستخدمي Linux؟ راجع [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
