---
title: "TokenLens: JWT 디코더, 디버거 및 서명 검증 도구"
description: "어떤 JSON Web Token이든 브라우저에서 디코딩·디버깅하고 Web Crypto API로 서명(HS/RS/ES/PS)을 암호학적으로 검증하세요. 100% 클라이언트 사이드 — 토큰은 기기를 벗어나지 않습니다."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["jwt 디코더", "jwt 디버거", "jwt 서명 검증", "json web token", "jwt 검증기", "jwt 온라인 디코딩", "rs256", "es256", "hs256", "클라이언트 사이드 jwt"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — JWT 디코더 및 서명 검증 도구", "description": "HS, RS, ES, PS 알고리즘을 지원하는 무료 클라이언트 사이드 JWT 디코더, 클레임 디버거 및 Web Crypto 서명 검증 도구.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## TokenLens의 기능

TokenLens는 모든 JSON Web Token을 브라우저에서 직접 디코딩하여 헤더, 페이로드, 등록된 모든 클레임을 쉬운 언어로 보여줍니다 — issuer, subject, audience, 그리고 토큰이 발급·유효화·만료되는 정확한 현지 시간까지. 이어서 자신의 시크릿이나 공개 키로 Web Crypto API를 통해 **서명을 암호학적으로 검증**할 수 있습니다.

서버 기반 디코더와 달리 토큰은 이 페이지를 절대 벗어나지 않습니다. 업로드도, 로그도, 네트워크 요청도 없습니다. 토큰에 운영 환경 클레임이나 개인정보가 담겨 있어 타사 서버에 붙여넣을 수 없을 때 꼭 필요한 방식입니다.

## 지원 알고리즘

- **HMAC** — HS256, HS384, HS512 (공유 시크릿으로 검증)
- **RSA** — RS256/384/512 및 PS256/384/512 (PEM 공개 키 또는 JWK로 검증)
- **ECDSA** — ES256, ES384, ES512 (EC 공개 키 또는 JWK로 검증)

토큰을 붙여넣어 시작하거나, 샘플을 불러와 검증된 HS256 서명을 확인하세요.
