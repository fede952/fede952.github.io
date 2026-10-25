---
title: "Codificar e Decodificar Base64 (UTF-8)"
description: "Codifique texto em Base64 ou decodifique Base64 e Base64URL para texto, com suporte completo a UTF-8 para acentos e emoji. Grátis, na hora, no navegador."
intro: "Converta texto em **Base64** e vice-versa. A codificação é segura para UTF-8, e a decodificação também aceita a variante **Base64URL** usada em JWTs e APIs web, com ou sem preenchimento `=`. Nada do que você cola sai desta página."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["codificar base64", "decodificar base64", "base64 decoder", "base64 online", "decodificar base64url", "base64 para texto", "base64 utf-8", "conversor base64"]
tags: ["codificação", "ferramentas-dev", "base64", "ferramenta"]
app_category: "DeveloperApplication"
tool_partial: "base64-converter"
howto:
  - "Digite ou cole em **Texto de entrada**: texto comum para codificar ou uma string Base64 para decodificar."
  - "Clique em **Codificar em Base64** para transformar o texto em Base64. Acentos, ç, alfabetos não latinos e emoji são codificados em UTF-8."
  - "Clique em **Decodificar Base64** para voltar ao texto. São aceitos Base64 padrão, Base64URL (`-` e `_`), preenchimento faltando e quebras de linha."
  - "Leia o resultado em **Resultado** e clique em **Copiar** para mandá-lo para a área de transferência."
  - "Se os bytes decodificados não forem UTF-8 válido, a ferramenta avisa: provavelmente são dados binários (uma imagem, um arquivo compactado ou uma chave), e não texto."
faq:
  - q: "Para que serve o Base64?"
    a: "O Base64 representa dados binários com 64 caracteres ASCII imprimíveis, para que possam passar por sistemas que só lidam com texto: anexos de e-mail (MIME), data URLs em HTML e CSS, payloads JSON, cabeçalhos de autenticação HTTP Basic, Secrets do Kubernetes e as três partes de um JSON Web Token."
  - q: "Base64 é criptografia?"
    a: "Não. É uma codificação sem chave: qualquer um decodifica na hora, como esta página mostra. Nunca use Base64 para esconder senhas ou segredos; os Secrets do Kubernetes, por exemplo, são só codificados em Base64, não criptografados, a menos que você ative a criptografia em repouso."
  - q: "Qual a diferença entre Base64 e Base64URL?"
    a: "O Base64URL (RFC 4648, seção 5) troca `+` por `-` e `/` por `_` para que o resultado seja seguro em URLs e nomes de arquivo, e normalmente remove o preenchimento `=`. JWTs e muitas APIs usam essa variante. Esta ferramenta decodifica as duas; ao codificar, gera Base64 padrão."
  - q: "Por que meu texto decodificado saiu estranho?"
    a: "Ou a entrada não era texto desde o início (por exemplo, uma imagem ou um fluxo gzip), ou o texto original foi codificado com outro conjunto de caracteres, como Latin-1 em vez de UTF-8. A ferramenta decodifica como UTF-8 e avisa quando os bytes não são UTF-8 válido."
  - q: "Por que o Base64 fica cerca de um terço maior que o original?"
    a: "Cada 3 bytes de entrada viram 4 caracteres Base64, porque cada caractere carrega 6 bits (2⁶ = 64). São 33% a mais, além de até dois caracteres `=` de preenchimento no final. Uma imagem de 30 KB vira uma data URL de 40 KB."
  - q: "O texto que eu colo é enviado para algum lugar?"
    a: "Não. A codificação e a decodificação usam as funções nativas do navegador `btoa`, `atob`, `TextEncoder` e `TextDecoder` dentro desta página. Nada é enviado nem guardado."
---

## Como funciona

### Codificação

A função `btoa()` do JavaScript só entende caracteres da faixa Latin-1, então chamá-la direto em `"Ação €"` gera um erro. A ferramenta evita isso codificando do jeito certo:

1. O `TextEncoder` converte o texto em **bytes UTF-8**: `ç` vira `C3 A7`, `€` vira `E2 82 AC`.
2. Cada byte é transformado em um caractere de um byte, e o `btoa()` converte essa string de bytes em Base64.

O Base64 trabalha em grupos de **3 bytes = 24 bits**, divididos em quatro valores de 6 bits, cada um ligado a um caractere do alfabeto `A–Z a–z 0–9 + /`. Quando o tamanho da entrada não é múltiplo de 3, o último grupo é completado com `=`:

| Texto | Bytes UTF-8 | Base64 |
|---|---|---|
| `Man` | `4D 61 6E` | `TWFu` |
| `Ma` | `4D 61` | `TWE=` |
| `M` | `4D` | `TQ==` |
| `é` | `C3 A9` | `w6k=` |

### Decodificação

A decodificação faz o caminho inverso, com alguma tolerância para entradas do mundo real:

- Todos os espaços e quebras de linha são removidos (o MIME quebra o Base64 a cada 76 caracteres).
- Os caracteres **Base64URL** `-` e `_` voltam a ser `+` e `/`, e o preenchimento `=` que faltar é restaurado, então dá para colar um segmento de JWT do jeito que está.
- O `atob()` transforma o Base64 em bytes e o `TextDecoder` com `fatal: true` os interpreta como UTF-8. Se os bytes não forem UTF-8 válido, a ferramenta ainda mostra uma decodificação aproximada, mas avisa que provavelmente são dados binários.
- Uma string cujo tamanho dividido por 4 deixa resto 1 nunca pode ser Base64 válido, e é recusada com uma mensagem clara.

## Casos de uso

- **Ler um JWT na mão.** Cole o segmento do meio de um token para ver os claims em JSON (para verificar a assinatura, use o JWT Inspector).
- **Kubernetes e Docker.** Decodifique os valores de um manifesto Secret ou codifique um valor antes de colocá-lo em `data:`.
- **Autenticação HTTP Basic.** Decodifique um cabeçalho `Authorization: Basic …` para ver o `usuario:senha` que ele carrega, ou monte um para uma requisição de teste.
- **Data URLs e e-mail.** Inspecione URIs `data:` e partes MIME no código-fonte de um e-mail.
- **Depurar APIs.** Muitas APIs codificam em Base64 campos binários ou JSON aninhado; decodifique para ver o que foi realmente enviado.
