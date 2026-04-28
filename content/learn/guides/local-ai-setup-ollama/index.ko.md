---
title: "AI 비용을 그만 내세요: DeepSeek & Llama 3를 무료로 로컬에서 실행하는 방법"
date: 2025-02-02
description: "Ollama를 사용하여 DeepSeek, Llama 3 같은 강력한 AI 모델을 내 PC에서 무료로 실행하는 방법을 알아보세요. 완전한 프라이버시, 월 비용 제로, 오프라인 작동."
tags: ["AI", "Ollama", "Privacy", "Tutorial", "LocalLLM"]
categories: ["Guides", "Artificial Intelligence"]
author: "Federico Sella"
draft: false
---

강력한 AI 어시스턴트를 사용하기 위해 월 20달러의 구독료가 필요하지 않습니다. **Ollama**라는 무료 오픈소스 도구를 사용하면 **Meta의 Llama 3**와 **DeepSeek-R1**을 포함한 최첨단 대규모 언어 모델을 자신의 컴퓨터에서 직접 실행할 수 있습니다. 클라우드 없이. 계정 없이. 데이터가 기기를 떠나는 일도 없습니다.

이 가이드는 10분 이내에 전체 설정을 완료하도록 안내합니다.

## 왜 AI를 로컬에서 실행해야 할까요?

### 완전한 프라이버시

클라우드 AI 서비스를 사용하면 입력하는 모든 프롬프트가 원격 서버로 전송됩니다. 코드 스니펫, 비즈니스 아이디어, 개인적인 질문——모든 것이 포함됩니다. **로컬 LLM**을 사용하면 대화가 내 하드웨어에 남습니다. 그것뿐입니다.

### 월 비용 제로

ChatGPT Plus는 월 20달러. Claude Pro는 월 20달러. GitHub Copilot은 월 10달러. 로컬 모델은 초기 다운로드 후 **완전히 무료**입니다. 모델은 오픈소스이며 자유롭게 사용할 수 있습니다.

### 오프라인 작동

비행기 안? Wi-Fi 없는 오두막? 상관없습니다. 로컬 모델은 CPU와 RAM만으로 완전히 실행됩니다——인터넷 연결이 필요하지 않습니다.

---

## 사전 준비

GPU나 고급 워크스테이션이 필요하지 않습니다. 최소 요건은 다음과 같습니다:

- **운영 체제:** Windows 10/11, macOS 12+ 또는 Linux
- **RAM:** 최소 8 GB (큰 모델에는 16 GB 권장)
- **디스크 공간:** 애플리케이션과 모델 하나에 약 5 GB 여유 공간
- **선택 사항:** 전용 GPU(NVIDIA/AMD)는 추론을 가속하지만 **필수는 아닙니다**

---

## 1단계: Ollama 다운로드 및 설치

**Ollama**는 단일 명령어로 LLM을 다운로드, 관리, 실행할 수 있는 경량 런타임입니다. 모든 플랫폼에서 설치가 간단합니다.

### Windows

1. [ollama.com](https://ollama.com)을 방문하여 **Download for Windows**를 클릭합니다.
2. 설치 프로그램을 실행합니다——약 1분 정도 걸립니다.
3. 설치 후 Ollama가 자동으로 백그라운드에서 실행됩니다.

### macOS

두 가지 옵션이 있습니다:

```bash
# 옵션 A: Homebrew (권장)
brew install ollama

# 옵션 B: 직접 다운로드
# https://ollama.com에서 .dmg 다운로드
```

### Linux

하나의 명령어로 모든 것이 해결됩니다:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

설치 후 정상 작동하는지 확인합니다:

```bash
ollama --version
```

터미널에 버전 번호가 표시되어야 합니다.

---

## 2단계: 첫 번째 모델 실행 — 마법의 명령어

바로 이 순간입니다. 터미널을 열고 입력하세요:

```bash
ollama run llama3
```

이것이 전부입니다. Ollama는 첫 실행 시 **Llama 3 8B** 모델(약 4.7 GB)을 다운로드한 후 터미널에서 바로 대화형 채팅 세션을 시작합니다:

```
>>> 당신은 누구인가요?
저는 Meta에서 훈련한 대규모 언어 모델인 Llama입니다.
오늘 무엇을 도와드릴까요?

>>> 숫자가 소수인지 확인하는 Python 함수를 작성해주세요.
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
```

### 추론 작업에는 DeepSeek-R1을 사용해 보세요

**DeepSeek-R1**은 수학, 논리, 단계별 문제 해결에 뛰어납니다:

```bash
ollama run deepseek-r1
```

### 기타 인기 모델

| 모델 | 명령어 | 최적 용도 |
|---|---|---|
| Llama 3 8B | `ollama run llama3` | 일반 채팅, 코딩 |
| DeepSeek-R1 8B | `ollama run deepseek-r1` | 수학, 논리, 추론 |
| Mistral 7B | `ollama run mistral` | 빠르고 효율적인 올라운더 |
| Gemma 2 9B | `ollama run gemma2` | Google의 오픈 모델 |
| Qwen 2.5 7B | `ollama run qwen2.5` | 다국어 작업 |

`ollama list`로 다운로드한 모델을 확인하고, `ollama rm <모델명>`으로 모델을 삭제하여 디스크 공간을 확보할 수 있습니다.

---

## 3단계: Open WebUI로 채팅 인터페이스 추가 (선택)

터미널도 잘 작동하지만, 세련된 **ChatGPT 스타일 인터페이스**를 원한다면 **Open WebUI**를 설치하세요. 가장 빠른 방법은 Docker입니다:

```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data --name open-webui \
  --restart always ghcr.io/open-webui/open-webui:main
```

그런 다음 브라우저에서 [http://localhost:3000](http://localhost:3000)을 열어보세요. 대화 기록, 모델 전환, 파일 업로드 등을 갖춘 익숙한 채팅 인터페이스를 사용할 수 있습니다——모두 로컬 Ollama 인스턴스에 연결됩니다.

> **Docker가 없나요?** [Chatbox](https://chatboxai.app) (데스크톱 앱)이나 [Ollama Web UI](https://github.com/ollama-webui/ollama-webui)처럼 Docker가 필요 없는 경량 프론트엔드도 있습니다.

---

## 로컬 AI vs. 클라우드 AI: 전체 비교

| 특징 | 로컬 AI (Ollama) | 클라우드 AI (ChatGPT, Claude) |
|---|---|---|
| **프라이버시** | 데이터가 절대 PC를 떠나지 않음 | 데이터가 원격 서버로 전송됨 |
| **비용** | 완전 무료 | 프리미엄 티어 월 20달러 |
| **인터넷 필요** | 아니요 — 완전히 오프라인 작동 | 예 — 항상 |
| **속도** | 하드웨어에 따라 다름 | 빠름 (서버 측 GPU) |
| **모델 품질** | 우수 (Llama 3, DeepSeek) | 우수 (GPT-4o, Claude) |
| **설정 노력** | 명령어 하나 | 계정 생성 |
| **커스터마이징** | 완전한 제어, 파인튜닝 | 제한적 |
| **데이터 보존** | 모든 것을 내가 관리 | 제공업체 정책 적용 |

**결론:** 클라우드 모델은 가장 큰 작업에서는 여전히 원시 성능에서 우위에 있지만, 일상적인 코딩 도움, 글쓰기, 브레인스토밍, Q&A에는 로컬 모델이 **충분하고도 남습니다** — 게다가 무료이고 프라이빗합니다.

---

## 마무리

로컬 AI 실행은 더 이상 비싼 GPU를 가진 연구자들만의 틈새 취미가 아닙니다. **Ollama**와 오픈소스 모델 생태계 덕분에, 현대적인 노트북을 가진 누구나 10분 이내에 프라이빗하고 무료이며 오프라인 가능한 AI 어시스턴트를 가질 수 있습니다.

기억해야 할 명령어:

```bash
# 설치 (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# 모델 실행
ollama run llama3

# 모델 목록 확인
ollama list
```

한번 시도해 보세요. 로컬 LLM의 속도와 프라이버시를 경험하면, 클라우드를 점점 덜 사용하게 될 수도 있습니다.

> 로컬 AI와 함께 코딩하면서 집중력이 필요하신가요? [ZenFocus 앰비언트 믹서와 포모도로 타이머](/ko/tools/zen-focus/)를 사용해 보세요 — 추적 없이 브라우저에서 완전히 작동하는 또 다른 도구입니다.
