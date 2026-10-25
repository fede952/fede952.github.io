---
title: "Gerador de hash e verificador de checksum"
description: "Gere hashes MD5, SHA-1, SHA-256 e SHA-512 de um texto, ou verifique um arquivo baixado com o checksum publicado. Roda no seu navegador, sem enviar nada."
intro: "Digite ou cole um texto para ver os hashes **MD5, SHA-1, SHA-256 e SHA-512** enquanto digita, ou **verifique um arquivo**: escolha um download, cole o checksum da página do autor e receba um claro **confere ou não confere**. Arquivos de qualquer tamanho são processados por partes num worker em segundo plano e nunca saem do seu dispositivo."
date: 2026-02-03
lastmod: 2026-10-26
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
  - "Para conferir um download, desça até **Verificar o checksum de um arquivo**, escolha o arquivo e cole o checksum fornecido pelo autor (um hash solto ou a linha de um arquivo SHA256SUMS). O algoritmo é definido pelo tamanho."
faq:
  - q: "Qual algoritmo de hash devo usar?"
    a: "Para verificação de integridade, impressões digitais e projetos novos, use SHA-256 (ou SHA-512). MD5 e SHA-1 estão quebrados para segurança: existem ataques de colisão práticos, então não devem ser usados em assinaturas ou certificados. Ainda servem para usos sem exigência de segurança, como chaves de cache ou para bater um checksum de um sistema antigo."
  - q: "Posso gerar o hash de uma senha com esta ferramenta?"
    a: "Você pode calcular o SHA-256 de qualquer string, mas um hash SHA simples é o jeito errado de guardar senhas: ele foi feito para ser rápido, então um atacante consegue testar bilhões de tentativas por segundo. Sistemas reais usam uma função de hash de senha lenta e com salt, como Argon2id, bcrypt, scrypt ou PBKDF2."
  - q: "Por que meu hash é diferente do de outra ferramenta?"
    a: "Quase sempre a entrada é diferente. Confira se há uma quebra de linha no final (`echo` adiciona uma; use `echo -n`), espaços, finais de linha do Windows `\\r\\n` ou outra codificação de texto. Esta ferramenta calcula o hash exatamente dos caracteres da caixa, codificados em UTF-8."
  - q: "Dá para gerar o hash de um arquivo?"
    a: "Sim. Use **Verificar o checksum de um arquivo** abaixo dos hashes de texto. O arquivo é lido no navegador em blocos por um worker em segundo plano (com a biblioteca hash-wasm, servida por este site), então até arquivos de vários gigabytes funcionam sem lotar a memória, e nada é enviado. Na linha de comando: `sha256sum arquivo` no Linux, `shasum -a 256 arquivo` no macOS e `Get-FileHash arquivo -Algorithm SHA256` no Windows PowerShell."
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

## Como verificar um download

Um checksum prova que o seu arquivo é, bit a bit, o arquivo do qual o autor calculou o hash. Ele detecta downloads interrompidos ou corrompidos e arquivos adulterados num espelho.

1. **Pegue o checksum na fonte oficial** — a página de download ou as notas de versão do projeto, de preferência em HTTPS. Um checksum hospedado ao lado do arquivo no mesmo espelho prova pouco: quem consegue trocar o arquivo também consegue trocar o checksum.
2. **Baixe o arquivo**, abra **Verificar o checksum de um arquivo** nesta página e escolha-o.
3. **Cole o checksum esperado.** Você pode colar a linha inteira de um arquivo `SHA256SUMS`, uma linha `SHA256 (arquivo) = …` ou a saída do PowerShell; a ferramenta encontra o hash e o algoritmo.
4. **Leia o resultado.** *Confere* significa que o arquivo é idêntico. *Não confere* significa que não é: apague e baixe de novo no site oficial. Um único caractere diferente já basta; não existe "quase igual".
5. **Prefira SHA-256 ou SHA-512.** MD5 e SHA-1 ainda detectam danos acidentais, mas colisões podem ser criadas de propósito, então não provam que o arquivo não foi trocado.

Para a verificação mais forte, alguns projetos também assinam seus arquivos de checksums com GPG ou Sigstore. Verificar essa assinatura prova quem publicou o checksum; esta ferramenta confere se o seu arquivo bate com ele.

## Casos de uso

- **Conferir um checksum.** Muitos projetos publicam o SHA-256 de uma string de versão ou de uma configuração pequena: cole o texto e compare.
- **Depurar assinaturas e APIs.** Confira o hash que uma API espera para um payload, ou o SHA-256 que entra em uma assinatura AWS Signature V4 ou na verificação de um webhook.
- **Chaves de cache e deduplicação.** Gere um identificador estável a partir do texto de uma URL, de uma consulta ou de um documento.
- **Aprender criptografia.** Veja o efeito avalanche ao vivo, compare os tamanhos dos resumos e entenda por que MD5 e SHA-1 foram aposentados para segurança.
- **Bater dados legados.** Recrie um valor MD5 ou SHA-1 que um sistema antigo guardou para migrá-lo para algo mais forte.
