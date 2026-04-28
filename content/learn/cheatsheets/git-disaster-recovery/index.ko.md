---
title: "Git 재난 복구: 실수 되돌리기와 히스토리 수정"
description: "개발자를 위한 비상 키트. 커밋 되돌리기, 머지 충돌 해결, 삭제된 브랜치 복구, git rebase vs merge 마스터하기를 배우세요."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git 재난 복구: 실수 되돌리기와 히스토리 수정",
    "description": "개발자를 위한 비상 키트. 커밋 되돌리기, 머지 충돌 해결, 삭제된 브랜치 복구, git rebase vs merge 마스터하기를 배우세요.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 변경 사항 되돌리기

"실수했다"의 세 기둥: reset, revert, restore. 각각 범위와 위험 수준이 다릅니다.

### git restore — 스테이징되지 않은 변경 사항 취소

```bash
# 단일 파일의 변경 사항 취소 (작업 디렉토리만)
git restore file.txt

# 모든 스테이징되지 않은 변경 사항 취소
git restore .

# 파일 스테이징 해제 (작업 디렉토리의 변경 사항은 유지)
git restore --staged file.txt

# 특정 커밋의 파일 버전으로 복원
git restore --source=abc1234 file.txt
```

### git reset — HEAD를 뒤로 이동

```bash
# 소프트 리셋: 커밋 취소, 변경 사항은 스테이징 상태 유지
git reset --soft HEAD~1

# 혼합 리셋 (기본값): 커밋 취소, 스테이징 해제, 파일은 유지
git reset HEAD~1

# 하드 리셋: 커밋 취소, 모든 변경 사항 영구 삭제
git reset --hard HEAD~1

# 특정 커밋으로 리셋
git reset --hard abc1234
```

> **--soft**는 모든 것을 스테이징 상태로 유지합니다. **--mixed**는 스테이징을 해제하지만 파일은 유지합니다. **--hard**는 모든 것을 삭제합니다. 확실하지 않을 때는 `--soft`를 사용하세요.

### git revert — 안전하게 커밋 되돌리기 (공개 히스토리)

```bash
# 특정 커밋을 되돌리는 새 커밋 생성
git revert abc1234

# 자동 커밋 없이 되돌리기 (변경 사항만 스테이징)
git revert --no-commit abc1234

# 머지 커밋 되돌리기 (부모 #1 유지)
git revert -m 1 <merge-commit-hash>
```

> 공유 브랜치에서는 `reset` 대신 `revert`를 사용하세요 — 히스토리를 다시 쓰지 않습니다.

---

## 히스토리 다시 쓰기

커밋 메시지가 부끄럽거나 브랜치 히스토리가 엉망일 때 사용합니다.

### git commit --amend

```bash
# 마지막 커밋 메시지 변경
git commit --amend -m "better message"

# 마지막 커밋에 빠뜨린 파일 추가
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (인터랙티브 리베이스)

```bash
# 마지막 3개 커밋을 다시 쓰기
git rebase -i HEAD~3
```

편집기에서 다음과 같이 사용할 수 있습니다:

| 명령어   | 효과                              |
|----------|-----------------------------------|
| `pick`   | 커밋을 그대로 유지                |
| `reword` | 커밋 메시지 변경                  |
| `edit`   | 커밋을 수정하기 위해 일시 중지    |
| `squash` | 이전 커밋에 병합                  |
| `fixup`  | squash와 같지만 메시지 삭제       |
| `drop`   | 커밋을 완전히 삭제                |

```bash
# 현재 브랜치를 main 위에 리베이스 (선형 히스토리)
git rebase main

# 충돌 해결 후 계속 진행
git rebase --continue

# 잘못된 리베이스 중단
git rebase --abort
```

> **리베이스 vs 머지:** 리베이스는 선형 히스토리를 만듭니다 (깔끔한 로그). 머지는 브랜치 토폴로지를 보존합니다 (공유 브랜치에서 더 안전). 다른 사람이 이미 풀한 커밋은 절대 리베이스하지 마세요.

---

## 복구

모든 것이 불타고 있을 때, 이 명령어들이 소화기입니다.

### git reflog — 생명줄

reflog는 모든 HEAD 이동을 기록합니다. 하드 리셋 이후에도 커밋은 여전히 남아 있습니다.

```bash
# reflog 보기 (최근 모든 HEAD 위치)
git reflog

# 출력 예시:
# abc1234 HEAD@{0}: reset: moving to HEAD~3
# def5678 HEAD@{1}: commit: add feature X
# 9ab0123 HEAD@{2}: commit: fix login bug

# reflog 항목으로 리셋하여 복구
git reset --hard HEAD@{1}

# 또는 잃어버린 커밋을 체리픽
git cherry-pick def5678
```

### git fsck — 댕글링 객체 찾기

```bash
# 도달할 수 없는 커밋과 블롭 찾기
git fsck --unreachable

# 잃어버린 커밋만 찾기
git fsck --lost-found
# 결과는 .git/lost-found/에 저장됨
```

### 삭제된 브랜치 복구

```bash
# 1단계: 삭제된 브랜치의 마지막 커밋 찾기
git reflog | grep "branch-name"
# 또는 커밋 메시지로 검색
git reflog | grep "feature I was working on"

# 2단계: 해당 커밋에서 브랜치 재생성
git branch recovered-branch abc1234

# 대안: 한 번에 찾아서 복원
git checkout -b recovered-branch HEAD@{5}
```

---

## 일반적인 재난 시나리오

### "잘못된 브랜치에 커밋했다"

```bash
# 1단계: 커밋 해시 확인
git log --oneline -1
# abc1234 accidental commit

# 2단계: 잘못된 브랜치에서 커밋 취소 (변경 사항 유지)
git reset --soft HEAD~1

# 3단계: 스태시, 브랜치 전환, 적용
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### "파일 추적을 중지하되 로컬에는 유지하고 싶다"

```bash
# git 추적에서 제거하되 디스크에는 파일 유지
git rm --cached secret-config.env

# .gitignore에 추가하여 향후 추적 방지
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "푸시를 되돌려야 한다"

```bash
# 안전한 방법: 커밋 되돌리기 (새 커밋 생성)
git revert abc1234
git push

# 최후의 수단: 강제 푸시 (공유 브랜치에서는 위험)
git reset --hard HEAD~1
git push --force-with-lease
```

### "머지에 충돌이 곳곳에 있다"

```bash
# 충돌이 있는 파일 확인
git status

# 충돌된 각 파일에서 충돌 마커를 찾으세요:
# <<<<<<< HEAD
# your changes
# =======
# their changes
# >>>>>>> branch-name

# 모든 충돌을 해결한 후:
git add .
git commit

# 또는 머지를 완전히 중단
git merge --abort
```

### git cherry-pick — 특정 커밋 가져오기

```bash
# 다른 브랜치에서 단일 커밋 적용
git cherry-pick abc1234

# 여러 커밋 적용
git cherry-pick abc1234 def5678

# 커밋 없이 체리픽 (스테이징만)
git cherry-pick --no-commit abc1234
```

---

## 빠른 참조 테이블

| 상황 | 명령어 |
|------|--------|
| 마지막 커밋 취소 (변경 사항 유지) | `git reset --soft HEAD~1` |
| 마지막 커밋 취소 (변경 사항 삭제) | `git reset --hard HEAD~1` |
| 푸시된 커밋 되돌리기 | `git revert <hash>` |
| 파일 변경 사항 취소 | `git restore <file>` |
| 파일 스테이징 해제 | `git restore --staged <file>` |
| 삭제된 브랜치 복구 | `git reflog` + `git branch name <hash>` |
| 마지막 커밋 메시지 수정 | `git commit --amend -m "new msg"` |
| 마지막 N개 커밋 스쿼시 | `git rebase -i HEAD~N` |
| 커밋을 올바른 브랜치로 이동 | `git reset --soft HEAD~1` + stash + switch |
| 파일 추적 중지 | `git rm --cached <file>` |
