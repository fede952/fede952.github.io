---
title: "SafeEnv: .env 파일 시크릿 및 API 키 스캐너"
description: "커밋하기 전에 .env 파일과 설정 스니펫에서 노출된 시크릿을 검사하세요 — AWS 키, GitHub·Stripe 토큰, 개인 키, URL 속 비밀번호, 고엔트로피 값. 100% 브라우저에서 실행되며 아무것도 업로드되지 않습니다."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["env 파일 스캐너", "시크릿 스캐너", "api 키 검사", "유출 시크릿 탐지", "env 스캔", "aws 키 유출", "git secrets", "클라이언트 사이드 시크릿 스캐너", "dotenv 보안"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — 시크릿 및 API 키 스캐너", "description": "커밋 전에 .env 파일과 설정에서 노출된 API 키, 토큰, 개인 키, 비밀번호를 찾아주는 무료 클라이언트 사이드 스캐너.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## 커밋 전에 스캔해야 하는 이유

공개 저장소에 `.env` 하나만 올라가도 끝입니다. 봇은 GitHub를 훑으며 새 AWS 키를 **1분 이내**에 찾아냅니다. SafeEnv는 커밋 전에 유출을 잡아냅니다. `.env`, `docker-compose.yml`, CI 설정, 코드 조각 등 어떤 설정이든 붙여넣으면 노출된 자격 증명을 줄 번호, 마스킹된 미리보기, 구체적인 조치 방법과 함께 표시합니다.

스캔은 이 페이지의 메모리 안에서만 실행됩니다. 업로드도, 로그도, 네트워크 요청도 없습니다. 실제 시크릿을 붙여넣는 도구라면 이것이 유일하게 허용 가능한 설계입니다. 페이지를 새로고침하면 모두 사라집니다.

## 탐지 항목

- **클라우드·API 토큰** — AWS 키, GitHub, GitLab, Stripe, Google, OpenAI, Anthropic, Slack, SendGrid, npm, PyPI, Telegram, Twilio
- **개인 키** — RSA/EC/OpenSSH/PGP PEM 블록
- **URL 속 자격 증명** — 비밀번호가 포함된 데이터베이스 연결 문자열과 basic-auth URL
- **일반 유출** — 하드코딩된 비밀번호와 고엔트로피 값. 플레이스홀더 인식으로 오탐 최소화

설정을 붙여넣어 스캔하거나, 샘플을 불러와 가짜 키에 모든 탐지기가 반응하는 모습을 확인하세요.
