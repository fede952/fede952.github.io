---
title: "Git 프로토콜: 필수 명령어 참조 가이드"
description: "긴급 수정, GPG 서명, 브랜치 작업 및 고급 워크플로우를 다루는 전술적 Git 치트시트. 모든 개발자와 해커가 암기해야 할 명령어."
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["git 명령어 치트시트", "git 커밋 취소", "git gpg 서명", "git 브랜치 명령어", "git reset 가이드", "git rebase 튜토리얼", "고급 git 명령어", "해커를 위한 git"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git 프로토콜: 필수 명령어 참조 가이드",
    "description": "긴급 수정, GPG 서명, 브랜치 작업 및 고급 워크플로우를 다루는 포괄적인 Git 명령어 치트시트.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## $ System_Init

모든 작업은 흔적을 남긴다. 모든 커밋은 체크포인트다. Git은 단순한 버전 관리가 아니다 — 모든 소프트웨어 프로젝트의 포렌식 백본이다. 이 필드 매뉴얼에는 매일 사용할 명령어와 모든 것이 망가졌을 때 당신을 구할 명령어가 포함되어 있다.

명령어는 미션 유형별로 구성되어 있다. 정확하게 실행하라.

---

## $ Emergency_Fixes

배포가 잘못되어 타임라인을 다시 작성해야 할 때.

### 마지막 커밋 취소하기 (변경사항을 스테이징에 유지)

```bash
# 마지막 커밋을 취소하지만 변경사항은 스테이징 영역에 유지
git reset --soft HEAD~1
```

### 마지막 커밋 취소하기 (스테이징에서 제거)

```bash
# 마지막 커밋을 취소하고 변경사항을 작업 디렉토리로 되돌림
git reset --mixed HEAD~1
```

### 핵 리셋 (모든 로컬 변경사항 파괴)

```bash
# 경고: 커밋되지 않은 모든 작업을 영구적으로 파괴합니다
git reset --hard HEAD~1
```

### 마지막 커밋 메시지 수정하기

```bash
# 새 커밋을 생성하지 않고 마지막 커밋 메시지의 오타를 수정
git commit --amend -m "수정된 커밋 메시지"
```

### 삭제된 브랜치 복구하기

```bash
# reflog에서 잃어버린 커밋 해시를 찾기
git reflog

# 복구된 해시로부터 브랜치를 재생성
git checkout -b recovered-branch abc1234
```

### 히스토리를 다시 작성하지 않고 커밋 되돌리기

```bash
# 특정 커밋을 취소하는 새 커밋을 생성 (공유 브랜치에 안전)
git revert <commit-hash>
```

---

## $ Stealth_Mode

암호화 서명 및 신원 확인. 커밋이 진짜임을 증명하라.

### GPG 서명 설정하기

```bash
# 사용 가능한 GPG 키 목록 표시
gpg --list-secret-keys --keyid-format=long

# Git에게 어떤 키를 사용할지 알림
git config --global user.signingkey YOUR_KEY_ID

# 모든 커밋에 대한 자동 서명 활성화
git config --global commit.gpgsign true
```

### 단일 커밋 서명하기

```bash
# 특정 커밋을 수동으로 서명
git commit -S -m "signed: verified deployment"
```

### 커밋 서명 검증하기

```bash
# 마지막 커밋의 서명 확인
git log --show-signature -1

# 전체 로그에서 서명 검증
git log --pretty="format:%h %G? %aN %s"
```

### 릴리스용 태그 서명하기

```bash
# 서명된 릴리스 태그 생성
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# 서명된 태그 검증
git tag -v v1.0.0
```

---

## $ Branch_Operations

병렬 개발을 위한 전술적 브랜치 관리.

### 새 브랜치 생성 및 전환하기

```bash
# 기능 브랜치를 생성하고 한 번의 명령으로 전환
git checkout -b feature/new-module
```

### 모든 브랜치 나열하기 (로컬 및 원격)

```bash
# 원격 추적 브랜치를 포함한 모든 브랜치 표시
git branch -a
```

### 브랜치 안전하게 삭제하기

```bash
# 로컬 브랜치 삭제 (완전히 병합된 경우에만)
git branch -d feature/old-module

# 로컬 브랜치 강제 삭제 (병합되지 않아도)
git branch -D feature/abandoned-experiment
```

### 원격 브랜치 삭제하기

```bash
# 원격 저장소에서 브랜치 제거
git push origin --delete feature/old-module
```

### main에 리베이스하기 (선형 히스토리)

```bash
# 최신 main 위에 브랜치 커밋을 재적용
git checkout feature/my-work
git rebase main
```

### 대화형 리베이스 (스쿼시, 재정렬, 편집)

```bash
# 마지막 3개의 커밋을 대화형으로 재작성
git rebase -i HEAD~3
```

---

## $ Reconnaissance

결정을 내리기 전에 저장소 상태를 검사한다.

### 그래프가 포함된 간결한 로그 보기

```bash
# 브랜치 그래프 시각화가 포함된 한 줄 로그
git log --oneline --graph --all --decorate
```

### 스테이징 영역의 변경사항 표시하기

```bash
# 스테이징된 변경사항을 마지막 커밋과 비교
git diff --cached
```

### 파일 blame하기 (각 줄을 변경한 사람 찾기)

```bash
# 파일의 각 줄에 대한 작성자 및 커밋 표시
git blame path/to/file.py
```

### 커밋 메시지 검색하기

```bash
# 메시지에 특정 키워드가 포함된 커밋 찾기
git log --grep="bugfix" --oneline
```

### 버그를 도입한 커밋 찾기

```bash
# 코드를 망가뜨린 변경사항을 찾기 위한 커밋 이진 검색
git bisect start
git bisect bad          # 현재 커밋이 망가짐
git bisect good abc1234 # 이 오래된 커밋은 작동했음
# Git이 테스트할 커밋을 체크아웃합니다
```

---

## $ Stash_Operations

커밋 없이 작업을 임시로 보관한다.

### 현재 변경사항 스태시하기

```bash
# 커밋되지 않은 변경사항을 임시 스택에 저장
git stash push -m "work in progress: auth module"
```

### 모든 스태시 나열하기

```bash
# 모든 스태시 항목 보기
git stash list
```

### 스태시 적용 및 제거하기

```bash
# 가장 최근 스태시를 복원하고 스택에서 제거
git stash pop

# 인덱스별로 특정 스태시 복원
git stash apply stash@{2}
```

### 스태시에서 브랜치 생성하기

```bash
# 스태시를 적절한 기능 브랜치로 전환
git stash branch feature/from-stash stash@{0}
```

---

## $ Advanced_Protocols

복잡한 시나리오를 위한 강력한 명령어.

### 다른 브랜치에서 커밋 체리픽하기

```bash
# 한 브랜치의 특정 커밋을 현재 브랜치에 적용
git cherry-pick <commit-hash>
```

### 추적되지 않은 파일 정리하기

```bash
# 삭제될 내용 미리보기
git clean -n

# 추적되지 않은 파일 및 디렉토리 삭제
git clean -fd
```

### 패치 파일 생성하기

```bash
# 마지막 커밋을 휴대용 패치 파일로 내보내기
git format-patch -1 HEAD

# 패치 파일 적용
git am < patch-file.patch
```

### 얕은 클론 (대역폭 절약)

```bash
# 최신 커밋만 클론 (전체 히스토리 없음)
git clone --depth 1 https://github.com/user/repo.git
```
