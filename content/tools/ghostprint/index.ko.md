---
title: "GhostPrint: 브라우저 지문 테스트 — 당신은 얼마나 추적당하나?"
description: "브라우저가 모든 사이트에 넘기는 보이지 않는 지문 —— GPU, 캔버스, 폰트, 오디오 등 —— 을 확인하고 고유성 점수를 받으세요. 100% 브라우저에서 실행되며 아무것도 업로드되지 않습니다."
date: 2026-07-06
tags: ["privacy", "security", "developer-tools", "fingerprinting"]
keywords: ["브라우저 지문 테스트", "나는 고유한가", "기기 지문", "캔버스 지문", "얼마나 추적당하나", "브라우저 핑거프린팅", "webgl 지문", "오디오 지문", "온라인 프라이버시 테스트", "추적 방지 테스트"]
layout: "tool"
draft: false
tool_file: "/tools/ghostprint/"
tool_height: "2200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "GhostPrint — 브라우저 지문 테스트", "description": "GPU, 캔버스, 오디오, 폰트 등을 바탕으로 브라우저가 얼마나 고유하고 추적 가능한지 점수를 매기는 무료 클라이언트 사이드 지문 테스트.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## 왜 지문이 쿠키를 이기는가

쿠키는 차단하기 쉽습니다. 하지만 **브라우저 지문**은 그렇지 않습니다. 기기, GPU, 폰트, 화면, 설정이 결합되는 정확한 방식이 하나의 식별자를 만들어 사이트를 넘나들며 당신을 따라다닙니다 —— 그리고 **시크릿 모드, 삭제된 쿠키, 대부분의 "비공개" 브라우징을 뚫고 살아남습니다.** GhostPrint는 몇 초 만에 당신의 지문을 보여주며, 고유성 점수와 유출되는 모든 신호의 분석을 제공합니다.

핵심은 이것입니다. 아래의 모든 신호는 **당신의 브라우저 안에서** 읽히고 **어디에도** 전송되지 않습니다 —— 업로드도, 로그도, 서버도 없습니다. 하지만 당신이 방문하는 어떤 사이트든 권한 요청 없이 이 값들을 조용히 읽을 수 있고, 광고·이상거래 탐지 네트워크가 바로 그렇게 합니다. 페이지를 새로고침하면 데이터는 사라지지만, 추적자들은 그 버튼을 주지 않습니다.

## GhostPrint가 읽는 것

- **하드웨어와 GPU** — 그래픽 칩(WebGL 경유), CPU 코어, 메모리, 화면 정보
- **렌더링 지문** — 캔버스와 오디오 해시: 당신의 환경에 고유한 픽셀·샘플 단위의 특성
- **환경** — 설치된 폰트, 시간대, 언어, 플랫폼, 표시 설정
- **프라이버시 신호** — 쿠키, Do-Not-Track, Global Privacy Control 상태

## 유령을 흐리게 하는 법

- **Tor Browser**가 최고 표준입니다 —— 모든 사용자가 의도적으로 똑같아 보이도록 만들어집니다.
- **Firefox**는 `privacy.resistFingerprinting`을 제공하고, **Brave**는 기본적으로 캔버스와 오디오를 무작위화합니다.
- 지문 방지 확장 프로그램과 WebGL 비활성화가 도움이 됩니다 —— 그리고 역설적으로, 특이한 하드웨어와 희귀 폰트는 당신을 *더* 식별하기 쉽게 만듭니다.

위의 스캔을 실행해 고유성 점수를 확인하고, 공유용 카드를 다운로드해 다른 브라우저와 비교해 보세요.
