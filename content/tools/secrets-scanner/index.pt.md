---
title: "Secrets Scanner: Encontre Chaves de API"
description: "Cole um .env, arquivo de configuração ou código e encontre chaves de API, tokens, chaves privadas e senhas expostas antes do commit. Tudo roda localmente."
intro: "O **SafeEnv** procura credenciais expostas em um texto: chaves da AWS, GitHub, Stripe, OpenAI e Slack, blocos de chaves privadas, senhas em strings de conexão e valores de alta entropia ao lado de nomes como `SECRET` ou `TOKEN`. Cole ou arraste um arquivo: a análise acontece inteiramente no seu navegador."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["secrets scanner", "encontrar chave de api no código", "scanner de arquivo env", "senha hardcoded", "detectar credenciais expostas", "vazamento de token github", "detecção de segredos online", "chave de api exposta"]
tags: ["segurança", "devsecops", "segredos", "ferramenta"]
app_category: "DeveloperApplication"
tool_file: "/tools/secrets-scanner/"
tool_title: "SafeEnv, scanner de segredos"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Cole na caixa o conteúdo de um `.env`, `docker-compose.yml`, configuração de CI, arquivo Terraform ou trecho de código, ou use **Scan a file…**, ou arraste um arquivo para cima dela."
  - "Clique em **Scan for secrets**. Um arquivo de configuração típico é analisado em poucos milissegundos."
  - "Leia os indicadores de resumo (critical, high, medium, low, info) e a lista de achados, ordenada por gravidade e depois por número de linha."
  - "Cada achado mostra a regra que disparou, a linha, o valor mascarado (só os quatro primeiros e os quatro últimos caracteres) e o que fazer."
  - "Resolva primeiro os críticos: troque a credencial, tire-a do arquivo e do histórico do git e carregue-a de um gerenciador de segredos ou variável de ambiente. **Copy report** gera um resumo em texto para um chamado."
faq:
  - q: "É seguro colar segredos reais neste scanner?"
    a: "O scanner é JavaScript rodando nesta página e não faz requisições de rede com o seu texto, então nada chega aos nossos servidores. Na tela aparecem valores mascarados, nunca os segredos completos. Mesmo assim, se encontrar uma chave real de produção, considere-a comprometida e troque-a."
  - q: "Que tipos de segredo ele detecta?"
    a: "Vinte formatos específicos, entre eles access key ID e secret key da AWS, tokens do GitHub e do GitLab, chaves live e de teste do Stripe, chaves de API do Google, da OpenAI e da Anthropic, tokens e webhooks do Slack, chaves do SendGrid, npm, PyPI, bots do Telegram e Twilio, JSON Web Tokens, blocos de chaves privadas e credenciais dentro de URLs de banco de dados ou HTTP. Uma segunda passada sinaliza valores de alta entropia e senhas hardcoded em qualquer linha `CHAVE=VALOR`."
  - q: "Por que um valor é marcado como \"high entropy\"?"
    a: "Strings com cara de aleatórias são exatamente como segredos gerados se parecem. O scanner calcula a entropia de Shannon de cada valor com 20 ou mais caracteres e o sinaliza a partir de 4,3 bits por caractere. Valores ao lado de nomes com secret, token, password, key ou auth ganham gravidade maior. Hashes, UUIDs e IDs de build também podem disparar, então olhe o contexto."
  - q: "O que fazer se um segredo foi parar em um commit do git?"
    a: "Apagar a linha em um novo commit não basta: o segredo continua no histórico e em cada clone. Primeiro troque ou revogue a credencial, depois reescreva o histórico com `git filter-repo` ou BFG Repo-Cleaner, faça force-push e peça aos colaboradores para clonar de novo. A troca da credencial é o passo que realmente protege você."
  - q: "Ele substitui ferramentas como Gitleaks ou o secret scanning do GitHub?"
    a: "Não, complementa. Use um hook de pre-commit ou um scanner na CI para cada commit, e a push protection do GitHub nos seus repositórios. O SafeEnv é para os momentos entre uma coisa e outra: conferir um trecho antes de colá-lo em um chat, um chamado ou um assistente de IA, ou revisar uma configuração que alguém mandou."
  - q: "Por que valores de exemplo aparecem como info?"
    a: "Linhas como `API_KEY=your-api-key-here` ou `PASSWORD=${DB_PASSWORD}` têm forma de segredo, mas são modelos. O scanner reconhece os padrões de exemplo mais comuns (your-, changeme, example, xxx, `${VAR}`, `<value>`) e os mostra como info para você confirmar que são intencionais."
---

## Como funciona

O scanner é um pequeno motor de regras sem dependências, que passa duas vezes pelo texto.

### Passada 1: formatos de token conhecidos

Vinte expressões regulares reconhecem formatos que os fornecedores documentam publicamente, principalmente pelo prefixo fixo e pelo tamanho. Alguns exemplos do que as regras procuram:

| Regra | Assinatura reconhecida | Gravidade |
|---|---|---|
| Bloco de chave privada | `-----BEGIN … PRIVATE KEY-----` (RSA, EC, DSA, OpenSSH, PGP, criptografada) | Crítica |
| Access key ID da AWS | `AKIA`, `ASIA`, `ABIA` ou `ACCA` seguidos de 16 letras maiúsculas ou números | Crítica |
| Secret access key da AWS | Um valor Base64 de 40 caracteres atribuído a um nome como `aws_secret_access_key` | Crítica |
| Token do GitHub | Prefixos `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` ou `github_pat_` | Crítica |
| Chave live do Stripe | Prefixos `sk_live_` / `rk_live_` | Crítica |
| Chave da OpenAI / Anthropic | Prefixos `sk-proj-`, `sk-svcacct-`, `sk-ant-` | Crítica |
| Chave de API do Google | `AIza` seguido de 35 caracteres | Alta |
| Token / webhook do Slack | Tokens `xox[baprs]-`, URLs `hooks.slack.com/services/…` | Alta |
| Credenciais em uma URI | `postgres://usuario:senha@host`, e também MySQL, MongoDB, Redis, AMQP, FTP e basic auth HTTP | Alta |
| JSON Web Token | Três segmentos Base64URL começando com `eyJ` | Média |
| Chave de teste / publicável do Stripe | `sk_test_`, `pk_live_`, `pk_test_` | Baixa |

Cada ocorrência registra o número da linha (contando as quebras de linha anteriores) e uma versão **mascarada** do valor, que guarda só os quatro primeiros e os quatro últimos caracteres: o relatório em si nunca contém o segredo.

### Passada 2: análise genérica `CHAVE=VALOR`

As linhas que nenhuma regra específica capturou são lidas como atribuições, a sintaxe de `.env`, YAML e da maioria dos formatos de configuração (prefixos `export`, aspas e comentários `#` no fim da linha são tratados). Para cada valor com seis ou mais caracteres:

1. Se parecer um **valor de exemplo** (`your-…`, `changeme`, `example`, `xxxx`, `${VAR}`, `<value>`, `true/false/null`), ele é indicado como *info* quando o nome da chave parece de segredo, e ignorado caso contrário.
2. Valores com uma URL ou espaços são pulados, porque raramente são segredos sozinhos.
3. É calculada a **entropia de Shannon** H = −Σ p·log₂(p) sobre a frequência dos caracteres. Um valor com 20+ caracteres e H ≥ 4,3 bits por caractere é marcado como *high entropy*, com gravidade alta se o nome da chave tiver secret, token, passw, pwd, api_key, private, credential ou auth, e média nos demais casos.
4. Um valor de entropia menor atribuído a um nome tipo senha é indicado como *hardcoded password*.

Os achados são ordenados por gravidade e depois por linha. Nada é guardado: limpe a caixa ou feche a aba e o texto some.

### Limites

A análise por regex encontra *formatos*, não *validade*: ela não sabe se uma chave ainda está ativa. Também não enxerga segredos quebrados em várias linhas, criptografados ou codificados de jeitos incomuns. Por isso é uma checagem rápida, não um substituto da varredura na sua pipeline de CI.

## Casos de uso

- **Antes de compartilhar um trecho.** Confira uma configuração ou um stack trace antes de colar no Slack, em uma issue do GitHub, no Stack Overflow ou em um chatbot de IA.
- **Antes do primeiro commit.** Analise `.env.example`, `docker-compose.yml` e os arquivos de CI de um projeto novo para garantir que nenhum valor real escapou.
- **Revisar um pull request ou uma passagem de bastão.** Cole o diff dos arquivos de configuração e procure qualquer coisa crítica.
- **Resposta a incidentes.** Depois de um possível vazamento, analise logs ou configurações exportadas para listar todas as credenciais que precisam ser trocadas.
- **Ensinar bons hábitos.** O arquivo de exemplo mostra a um time, em segundos, quantos segredos cabem em um `.env` comum.
