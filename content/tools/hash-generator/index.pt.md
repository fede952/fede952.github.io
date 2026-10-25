---
title: "Gerador de Hash: MD5, SHA-256, SHA-512"
description: "Gere hashes MD5, SHA-1, SHA-256 e SHA-512 de qualquer texto enquanto digita, com suporte a UTF-8 e cópia com um clique. Calculado no seu navegador."
intro: "Digite ou cole um texto e veja de uma vez os hashes **MD5, SHA-1, SHA-256 e SHA-512**, atualizados enquanto você digita. A família SHA é calculada pela Web Crypto API do seu navegador; nada do que você insere é enviado."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["gerador de hash", "gerador sha256", "gerador md5", "hash sha512 online", "hash sha1", "texto para sha256", "calcular checksum", "calculadora de hash online"]
tags: ["criptografia", "hash", "ferramentas-dev", "ferramenta"]
app_category: "DeveloperApplication"
tool_partial: "hash-generator"
howto:
  - "Digite ou cole seu texto em **Texto de entrada**. Os quatro hashes são recalculados a cada tecla."
  - "Leia o resultado de que precisa: **MD5** (32 caracteres hexadecimais), **SHA-1** (40), **SHA-256** (64) ou **SHA-512** (128)."
  - "Clique em **Copiar** ao lado de um hash para enviá-lo à área de transferência."
  - "Para comparar com um hash que você recebeu, cole os dois em um editor ou compare caractere por caractere: um único caractere diferente significa entrada diferente."
  - "Clique em **Limpar tudo** para esvaziar a entrada e os resultados."
faq:
  - q: "Qual algoritmo de hash devo usar?"
    a: "Para verificação de integridade, impressões digitais e projetos novos, use SHA-256 (ou SHA-512). MD5 e SHA-1 estão quebrados para segurança: existem ataques de colisão práticos, então não devem ser usados em assinaturas ou certificados. Ainda servem para usos sem exigência de segurança, como chaves de cache ou para bater um checksum de um sistema antigo."
  - q: "Posso gerar o hash de uma senha com esta ferramenta?"
    a: "Você pode calcular o SHA-256 de qualquer string, mas um hash SHA simples é o jeito errado de guardar senhas: ele foi feito para ser rápido, então um atacante consegue testar bilhões de tentativas por segundo. Sistemas reais usam uma função de hash de senha lenta e com salt, como Argon2id, bcrypt, scrypt ou PBKDF2."
  - q: "Por que meu hash é diferente do de outra ferramenta?"
    a: "Quase sempre a entrada é diferente. Confira se há uma quebra de linha no final (`echo` adiciona uma; use `echo -n`), espaços, finais de linha do Windows `\\r\\n` ou outra codificação de texto. Esta ferramenta calcula o hash exatamente dos caracteres da caixa, codificados em UTF-8."
  - q: "Dá para gerar o hash de um arquivo?"
    a: "Não com esta página: ela trabalha com texto. Para arquivos, use a linha de comando: `sha256sum arquivo` no Linux, `shasum -a 256 arquivo` no macOS ou `Get-FileHash arquivo -Algorithm SHA256` no PowerShell do Windows."
  - q: "Um hash pode ser revertido ou descriptografado?"
    a: "Não. Um hash é uma função de mão única: não existe chave nem forma de calcular a entrada a partir da saída. Sites que \"descriptografam MD5\" só consultam tabelas de hashes pré-calculados de palavras comuns, e é exatamente por isso que entradas curtas ou comuns não ficam protegidas pelo hash."
  - q: "O que eu digito é enviado para algum servidor?"
    a: "Não. SHA-1, SHA-256 e SHA-512 são calculados com `crypto.subtle.digest()` e o MD5 com uma implementação em JavaScript, tudo dentro desta página. Não há requisições de rede com o que você digita."
---

## Como funciona

A cada alteração, a ferramenta lê a caixa de texto, converte em bytes com `TextEncoder` (UTF-8, então `é` vira dois bytes e um emoji quatro) e executa quatro funções de hash em paralelo com `Promise.all`:

- **SHA-1, SHA-256 e SHA-512** passam pela **Web Crypto API** nativa do navegador: `crypto.subtle.digest('SHA-256', bytes)` devolve um `ArrayBuffer`, que é convertido para hexadecimal minúsculo.
- **MD5** não faz parte da Web Crypto, porque é considerado quebrado, então é calculado por uma implementação compacta em JavaScript da RFC 1321 sobre os mesmos bytes UTF-8.

Os resultados são strings hexadecimais cujo tamanho é fixado pelo algoritmo, seja qual for o tamanho da entrada:

| Algoritmo | Tamanho | Caracteres hex | Situação |
|---|---|---|---|
| MD5 | 128 bits | 32 | Quebrado (colisões desde 2004) |
| SHA-1 | 160 bits | 40 | Quebrado (colisão prática, 2017) |
| SHA-256 | 256 bits | 64 | Seguro, o padrão mais comum |
| SHA-512 | 512 bits | 128 | Seguro, mais rápido em CPUs de 64 bits |

Duas propriedades tornam essas funções úteis. Elas são **determinísticas**: a mesma entrada sempre gera o mesmo hash, em qualquer máquina. E têm **efeito avalanche**: mude um caractere e cerca de metade dos bits de saída se invertem, por isso `Olá` e `olá` têm SHA-256 completamente diferentes. Os botões `Copiar` usam a Clipboard API, com alternativa para navegadores antigos.

### Texto, não arquivos

A entrada é o texto da caixa, então os hashes só batem com os de ferramentas de linha de comando quando os bytes são exatamente iguais. `printf 'Olá, Mundo!' | sha256sum` e esta ferramenta concordam; `echo 'Olá, Mundo!' | sha256sum` não, porque o `echo` acrescenta uma quebra de linha.

## Casos de uso

- **Conferir um checksum.** Muitos projetos publicam o SHA-256 de uma string de versão ou de uma configuração pequena: cole o texto e compare.
- **Depurar assinaturas e APIs.** Confira o hash que uma API espera para um payload, ou o SHA-256 que entra em uma assinatura AWS Signature V4 ou na verificação de um webhook.
- **Chaves de cache e deduplicação.** Gere um identificador estável a partir do texto de uma URL, de uma consulta ou de um documento.
- **Aprender criptografia.** Veja o efeito avalanche ao vivo, compare os tamanhos dos resumos e entenda por que MD5 e SHA-1 foram aposentados para segurança.
- **Bater dados legados.** Recrie um valor MD5 ou SHA-1 que um sistema antigo guardou para migrá-lo para algo mais forte.
