---
title: "إصلاح: fatal: refusing to merge unrelated histories"
description: "أصلح خطأ Git 'refusing to merge unrelated histories' عند تنفيذ pull أو merge. افهم لماذا يحدث وكيفية دمج مستودعين مستقلين بأمان."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "إصلاح: fatal: refusing to merge unrelated histories",
    "description": "كيفية إصلاح خطأ Git refusing to merge unrelated histories عند دمج مستودعات مستقلة.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ar"
  }
---

## الخطأ

تحاول سحب من مستودع بعيد أو دمج فرع ويرفض Git:

```
fatal: refusing to merge unrelated histories
```

يحدث هذا عادةً عند تنفيذ:

```bash
git pull origin main
```

والمستودعان المحلي والبعيد ليس لديهما commit سلف مشترك — يراهما Git كمشروعين منفصلين تمامًا ويرفض دمجهما تلقائيًا.

---

## الإصلاح السريع

أضف العلامة `--allow-unrelated-histories` لإجبار Git على دمج التاريخين المستقلين:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

أو إذا كنت تدمج فرعًا:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

سيحاول Git إجراء الدمج. إذا كانت هناك تعارضات في الملفات، قم بحلها بشكل طبيعي:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## لماذا يحدث هذا

يحدث هذا الخطأ عندما لا يتشارك مستودعا Git في أي سجل commits مشترك. السيناريوهات الأكثر شيوعًا:

### السيناريو 1: مستودع جديد مع تعارض README

أنشأت مستودعًا محليًا باستخدام `git init` وأجريت بعض الـ commits. ثم أنشأت مستودعًا على GitHub **مع README.md** (أو `.gitignore` أو `LICENSE`). الآن عند محاولة السحب، يحتوي المستودع البعيد على commit جذري لا يعرفه مستودعك المحلي.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**الوقاية:** عند إنشاء مستودع GitHub جديد لرفع مشروع محلي موجود، أنشئ المستودع البعيد **بدون** تهيئة (بدون README، بدون .gitignore، بدون ترخيص). ثم ارفع مباشرة.

### السيناريو 2: دمج مستودعين مستقلين

تريد دمج مشروعين منفصلين في مستودع واحد. نظرًا لأنهما أُنشئا بشكل مستقل، فلديهما أشجار commits مختلفة تمامًا.

### السيناريو 3: سجل مُعاد كتابته

قام شخص ما بتنفيذ `git rebase` أو `git filter-branch` على المستودع البعيد، مما أعاد كتابة الـ commits الجذرية. لم يعد سجل المستودع البعيد يتشارك في سلف مع نسختك المحلية.

---

## هل هو آمن؟

نعم — `--allow-unrelated-histories` يخبر Git ببساطة بالمتابعة في الدمج حتى لو لم يكن للفرعين قاعدة مشتركة. لا يحذف أو يكتب فوق أو يعيد ترتيب أي شيء. إذا كانت هناك ملفات متعارضة، سيضع Git علامة عليها كتعارضات ويتيح لك حلها يدويًا، تمامًا مثل الدمج العادي.

تمت إضافة هذه العلامة في **Git 2.9** (يونيو 2016). قبل هذا الإصدار، كان Git يسمح بعمليات الدمج غير المرتبطة افتراضيًا.

---

## موارد ذات صلة

أتقن عمليات الدمج المتقدمة وإعادة الترتيب وحل التعارضات مع [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — كل أمر Git يحتاجه المطور، منظم حسب سير العمل.
