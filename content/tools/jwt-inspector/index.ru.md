---
title: "TokenLens: декодер JWT, отладчик и проверка подписи"
description: "Декодируйте и отлаживайте любой JSON Web Token в браузере и криптографически проверяйте подпись (HS/RS/ES/PS) через Web Crypto API. 100% на стороне клиента — токен не покидает ваше устройство."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["декодер jwt", "отладка jwt", "проверка подписи jwt", "json web token", "валидатор jwt", "декодировать jwt онлайн", "rs256", "es256", "hs256", "jwt в браузере"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — декодер JWT и проверка подписи", "description": "Бесплатный клиентский декодер JWT, отладчик claims и проверка подписи Web Crypto с поддержкой алгоритмов HS, RS, ES и PS.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Что делает TokenLens

TokenLens декодирует любой JSON Web Token прямо в браузере и показывает заголовок, полезную нагрузку и каждый зарегистрированный claim простым языком — issuer, subject, audience и точное локальное время выпуска, начала действия и истечения токена. Затем вы можете **криптографически проверить подпись** через Web Crypto API, используя свой секрет или открытый ключ.

В отличие от серверных декодеров, токен никогда не покидает эту страницу: без загрузки, без логов, без сетевых запросов. Именно это нужно, когда токен содержит рабочие claims или персональные данные, а вставлять его в чужой сервер недопустимо.

## Поддерживаемые алгоритмы

- **HMAC** — HS256, HS384, HS512 (проверка общим секретом)
- **RSA** — RS256/384/512 и PS256/384/512 (проверка открытым ключом PEM или JWK)
- **ECDSA** — ES256, ES384, ES512 (проверка открытым ключом EC или JWK)

Вставьте токен, чтобы начать, или загрузите пример с проверенной подписью HS256.
