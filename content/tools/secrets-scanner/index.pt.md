---
title: "SafeEnv: Scanner de Segredos e Chaves de API para Arquivos .env"
description: "Escaneie seus arquivos .env e trechos de configuração em busca de segredos expostos antes do commit — chaves AWS, tokens do GitHub e Stripe, chaves privadas, senhas em URLs e valores de alta entropia. 100% no navegador: nada é enviado."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["scanner arquivo env", "scanner de segredos", "verificar chaves api", "detectar segredos expostos", "escanear env", "vazamento chave aws", "git secrets", "scanner de segredos lado cliente", "segurança dotenv"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — Scanner de Segredos e Chaves de API", "description": "Scanner gratuito no lado do cliente que encontra chaves de API, tokens, chaves privadas e senhas expostas em arquivos .env e configurações antes do commit.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Por que escanear antes do commit

Basta um `.env` colado em um repositório público: bots varrem o GitHub e encontram chaves AWS novas em **menos de um minuto**. O SafeEnv captura o vazamento antes do commit. Cole qualquer configuração — `.env`, `docker-compose.yml`, config de CI, trechos de código — e ele marca as credenciais expostas com número da linha, prévia mascarada e passos concretos de correção.

A varredura roda inteiramente na memória desta página. Sem upload, sem logs, sem requisição de rede — o único design aceitável para uma ferramenta onde você cola segredos reais. Recarregue a página e tudo desaparece.

## O que ele detecta

- **Tokens de nuvem e API** — chaves AWS, GitHub, GitLab, Stripe, Google, OpenAI, Anthropic, Slack, SendGrid, npm, PyPI, Telegram, Twilio
- **Chaves privadas** — blocos PEM RSA/EC/OpenSSH/PGP
- **Credenciais em URLs** — strings de conexão de banco de dados e URLs basic-auth com senhas embutidas
- **Vazamentos genéricos** — senhas hardcoded e valores de alta entropia, com detecção de placeholders para reduzir falsos positivos

Cole uma configuração para escanear, ou carregue o exemplo para ver todos os detectores disparando com chaves falsas.
