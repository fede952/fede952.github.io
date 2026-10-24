---
title: "Decodificar JWT e Verificar a Assinatura"
description: "Decodifique qualquer JSON Web Token, leia os claims e a expiração e verifique assinaturas HS256, RS256, PS256 ou ES256 com a Web Crypto API, no navegador."
intro: "Cole um **JSON Web Token** para ver o cabeçalho e o payload, conferir `exp`, `nbf` e `iat` em horário legível e verificar a assinatura com um segredo ou uma chave pública. A decodificação e a verificação acontecem no seu navegador: o token nunca é enviado."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["decodificar jwt", "jwt decoder", "verificar assinatura jwt", "jwt online", "validar token jwt", "jwt rs256", "expiração jwt", "jwt debugger"]
tags: ["segurança", "ferramentas-dev", "jwt", "ferramenta"]
app_category: "DeveloperApplication"
tool_file: "/tools/jwt-inspector/"
tool_title: "TokenLens: decodificador JWT e verificador de assinatura"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-read; clipboard-write"
howto:
  - "Cole um token na caixa ou clique em **Paste** para ler da área de transferência. **Load sample** carrega um token HS256 de exemplo."
  - "O token é dividido em suas três partes coloridas e decodificado na hora: cabeçalho e payload aparecem como JSON destacado."
  - "Veja os indicadores de status: algoritmo, `typ`, `kid` e se o token está expirado ou ainda não é válido. A tabela de claims traduz `exp`, `nbf` e `iat` em datas locais."
  - "Para verificar, cole o **segredo HMAC** para HS256/384/512 (marque *Secret is Base64URL-encoded* se for o caso) ou a **chave pública** do emissor em PEM ou JWK para os algoritmos RS, PS e ES."
  - "Clique em **Verify signature**. Verde significa que a assinatura bate com a chave e o token não foi alterado; vermelho, chave errada ou token adulterado."
faq:
  - q: "É seguro colar aqui um JWT de produção?"
    a: "A ferramenta roda inteiramente no navegador e não faz requisições de rede com o token, então nada é registrado do nosso lado. Mesmo assim, um access token válido é uma senha com data de validade: quem o vê pode usá-lo até expirar. Prefira tokens expirados ou de teste, e nunca use uma ferramenta que você não consegue inspecionar."
  - q: "Qual a diferença entre decodificar e verificar um JWT?"
    a: "Decodificar só desfaz a codificação Base64URL do cabeçalho e do payload, e qualquer um pode fazer isso: um JWT é assinado, não criptografado. Verificar é recalcular a assinatura sobre `header.payload` com a chave e conferir se bate com o terceiro segmento. Só a verificação garante que o token foi emitido por quem tem a chave e não foi modificado."
  - q: "Quais algoritmos ele verifica?"
    a: "HS256, HS384 e HS512 (HMAC com segredo compartilhado); RS256, RS384 e RS512 (RSA PKCS#1 v1.5); PS256, PS384 e PS512 (RSA-PSS); e ES256, ES384 e ES512 (ECDSA em P-256, P-384 e P-521). Tokens com `alg: none` ou outros algoritmos são decodificados, mas não verificados."
  - q: "Onde encontro a chave pública de um token RS256?"
    a: "A maioria dos provedores de identidade publica as chaves como JWKS em uma URL do tipo `https://issuer/.well-known/jwks.json`. Encontre a entrada cujo `kid` corresponde ao cabeçalho do token e cole esse objeto JWK. Uma chave pública PEM (`-----BEGIN PUBLIC KEY-----`) também funciona."
  - q: "Por que um token com \"alg\": \"none\" não é verificado?"
    a: "Porque não há o que verificar: o token diz que não está assinado. Aceitar tokens assim é uma vulnerabilidade clássica; o servidor deve decidir quais algoritmos aceita em vez de confiar no cabeçalho. O inspetor mostra o algoritmo em destaque justamente para isso chamar a atenção."
  - q: "A assinatura é válida, mas a API continua recusando o token. Por quê?"
    a: "Uma assinatura válida é só uma das verificações. Os servidores também validam `exp`, `nbf`, o emissor (`iss`), o público (`aud`) e muitas vezes os escopos. Confira os indicadores de status e a tabela de claims: um token expirado ou um público errado são as causas mais comuns."
  - q: "A ferramenta guarda o segredo ou a chave que eu colo?"
    a: "Não. As chaves são importadas com `crypto.subtle.importKey` como não extraíveis, usadas uma vez na verificação e descartadas junto com a página. Nada é gravado no armazenamento do navegador."
---

## Como funciona

### Decodificação

Um JWT são três segmentos Base64URL unidos por pontos: `header.payload.signature`. O inspetor divide a string, confere se há exatamente três segmentos, converte o Base64URL em Base64 padrão (trocando `-` por `+` e `_` por `/` e restaurando o preenchimento `=`), decodifica os bytes como UTF-8 e lê o cabeçalho e o payload com `JSON.parse`. Uma entrada malformada gera uma mensagem de erro específica em vez de uma tela em branco.

Os claims registrados do payload são explicados em uma tabela. Os claims de tempo `exp` (expiração), `nbf` (não antes de) e `iat` (emitido em) são valores **NumericDate**, segundos desde 1º de janeiro de 1970 UTC, então são convertidos para o seu horário local e para uma descrição relativa como "in 23 min" ou "3 days ago". A barra de status avisa sobre um token expirado, um ainda não válido e um sem `exp`.

### Verificação

A verificação usa a **Web Crypto API** embutida no navegador (`crypto.subtle`), não uma biblioteca de criptografia em JavaScript:

- A entrada assinada é a string ASCII `header.payload`, exatamente como aparece no token. Ela não é recodificada, e por isso um token editado à mão falha na verificação.
- **HS256/384/512**: o segredo é importado como chave HMAC bruta com SHA-256, SHA-384 ou SHA-512, e `crypto.subtle.verify('HMAC', …)` confere o MAC.
- **RS256/384/512**: a chave pública é importada como `RSASSA-PKCS1-v1_5` com o hash correspondente.
- **PS256/384/512**: importada como `RSA-PSS` e verificada com um salt do tamanho do hash (32, 48 ou 64 bytes), como exige a RFC 7518.
- **ES256/384/512**: importada como `ECDSA` em P-256, P-384 ou P-521. As assinaturas ECDSA de JWS são a concatenação bruta `r‖s`, o formato que a Web Crypto espera, então não é preciso converter para DER.

As chaves públicas podem ser informadas em **PEM/SPKI** (o Base64 entre as linhas `BEGIN/END PUBLIC KEY` é decodificado para DER) ou como objeto **JWK** em JSON. As chaves importadas não são extraíveis e só existem durante a verificação.

### Uma armadilha comum

Segredos HMAC costumam ser configurados como strings Base64. Se o seu backend decodifica o segredo antes de assinar, marque *Secret is Base64URL-encoded*; caso contrário a mesma string visível gera outra chave e a assinatura não bate.

## Casos de uso

- **Depurar autenticação.** Descubra por que uma requisição retorna 401: `exp` vencido, `aud` errado, um escopo faltando ou um token assinado por outra chave.
- **Validar a integração com um provedor de identidade.** Decodifique o ID token de um login OAuth/OIDC e verifique com a JWKS do provedor antes de escrever o backend.
- **Revisões de segurança e pentests.** Identifique tokens com `alg: none`, validade longa demais, dados sensíveis no payload ou um `kid` apontando para onde não deveria.
- **Rotação de chaves.** Confirme que tokens emitidos depois de uma rotação são verificados com a nova chave pública e os antigos com a anterior.
- **Ensino.** Mostre como um token é montado e por que Base64URL é codificação, não criptografia.
