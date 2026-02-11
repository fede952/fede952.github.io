---
title: "수정: fatal: refusing to merge unrelated histories"
description: "pull이나 merge 시 발생하는 Git의 'refusing to merge unrelated histories' 오류를 수정하세요. 왜 발생하는지 이해하고 두 개의 독립적인 저장소를 안전하게 결합하는 방법을 알아보세요."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "수정: fatal: refusing to merge unrelated histories",
    "description": "독립적인 저장소를 결합할 때 발생하는 Git의 refusing to merge unrelated histories 오류를 수정하는 방법.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ko"
  }
---

## 오류

원격 저장소에서 pull하거나 브랜치를 병합하려고 할 때 Git이 거부합니다:

```
fatal: refusing to merge unrelated histories
```

이 오류는 일반적으로 다음을 실행할 때 발생합니다:

```bash
git pull origin main
```

로컬과 원격 저장소에 공통 조상 커밋이 없는 경우 — Git은 이들을 완전히 별개의 두 프로젝트로 간주하고 자동으로 결합하는 것을 거부합니다.

---

## 빠른 수정

`--allow-unrelated-histories` 플래그를 추가하여 Git이 두 개의 독립적인 이력을 병합하도록 강제합니다:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

또는 브랜치를 병합하는 경우:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git이 병합을 시도합니다. 파일 충돌이 있으면 정상적으로 해결하세요:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## 왜 발생하는가

이 오류는 두 개의 Git 저장소가 공통 커밋 이력을 공유하지 않을 때 발생합니다. 가장 흔한 시나리오:

### 시나리오 1: README 충돌이 있는 새 저장소

`git init`으로 로컬 저장소를 만들고 몇 개의 커밋을 했습니다. 그런 다음 GitHub에서 **README.md**(또는 `.gitignore`나 `LICENSE`)**가 포함된** 저장소를 만들었습니다. 이제 pull하려고 하면 원격에는 로컬 저장소가 알지 못하는 루트 커밋이 있습니다.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**예방:** 기존 로컬 프로젝트를 push하기 위해 새 GitHub 저장소를 만들 때, 원격 저장소를 초기화**하지 않고** 만드세요(README 없음, .gitignore 없음, 라이선스 없음). 그런 다음 직접 push하세요.

### 시나리오 2: 두 개의 독립적인 저장소 병합

두 개의 별도 프로젝트를 하나의 저장소로 결합하고 싶은 경우. 독립적으로 생성되었기 때문에 완전히 다른 커밋 트리를 가지고 있습니다.

### 시나리오 3: 재작성된 이력

누군가가 원격에서 `git rebase`나 `git filter-branch`를 실행하여 루트 커밋을 재작성했습니다. 원격의 이력은 더 이상 로컬 복사본과 공통 조상을 공유하지 않습니다.

---

## 안전한가요?

네 — `--allow-unrelated-histories`는 단순히 두 브랜치에 공통 기반이 없어도 병합을 진행하라고 Git에 지시합니다. 아무것도 삭제하거나, 덮어쓰거나, 리베이스하지 않습니다. 충돌하는 파일이 있으면 Git이 충돌로 표시하고 일반 병합과 똑같이 수동으로 해결할 수 있게 합니다.

이 플래그는 **Git 2.9**(2016년 6월)에서 추가되었습니다. 해당 버전 이전에는 Git이 기본적으로 관련 없는 병합을 허용했습니다.

---

## 관련 리소스

[Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/)로 고급 병합, 리베이스 및 충돌 해결을 마스터하세요 — 개발자에게 필요한 모든 Git 명령어를 워크플로우별로 정리했습니다.
