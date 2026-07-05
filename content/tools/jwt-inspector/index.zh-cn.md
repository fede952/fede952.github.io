---
title: "TokenLens：JWT 解码器、调试器和签名验证工具"
description: "在浏览器中解码和调试任意 JSON Web Token，并用 Web Crypto API 对签名（HS/RS/ES/PS）进行加密验证。100% 客户端 —— 令牌绝不离开你的设备。"
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["jwt 解码器", "jwt 调试", "jwt 签名验证", "json web token", "jwt 校验器", "在线解码 jwt", "rs256", "es256", "hs256", "客户端 jwt"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens —— JWT 解码器和签名验证工具", "description": "免费的客户端 JWT 解码器、声明调试器和 Web Crypto 签名验证工具，支持 HS、RS、ES 和 PS 算法。", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## TokenLens 的功能

TokenLens 直接在浏览器中解码任意 JSON Web Token，并以清晰的语言展示头部、载荷和每一个注册声明 —— issuer、subject、audience，以及令牌签发、生效或过期的确切本地时间。随后，你可以使用自己的密钥或公钥，通过 Web Crypto API **对签名进行加密验证**。

与基于服务器的解码器不同，令牌绝不会离开此页面：没有上传、没有日志、没有网络请求。当令牌携带生产环境声明或个人数据、又不能粘贴到他人服务器时，这正是你所需要的。

## 支持的算法

- **HMAC** —— HS256、HS384、HS512（使用共享密钥验证）
- **RSA** —— RS256/384/512 和 PS256/384/512（使用 PEM 公钥或 JWK 验证）
- **ECDSA** —— ES256、ES384、ES512（使用 EC 公钥或 JWK 验证）

粘贴令牌即可开始，或加载示例查看已验证的 HS256 签名。
