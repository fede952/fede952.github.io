---
title: "Analisador de cabeçalhos de segurança e CSP"
description: "Cole cabeçalhos de resposta HTTP ou uma Content-Security-Policy para achar cabeçalhos ausentes, regras CSP fracas e cookies inseguros, com a correção. Local."
intro: "Cole os **cabeçalhos de resposta** de uma página — do `curl -sI` ou do DevTools do navegador — ou só uma **Content-Security-Policy**. O analisador verifica **HSTS**, **CSP**, **X-Content-Type-Options**, a proteção contra frames, **Referrer-Policy**, **Permissions-Policy**, **COOP**, **CORS** e cada **Set-Cookie**, explica cada problema e mostra a correção. Ele **não faz nenhuma requisição de rede**: lê só o que você cola, então também serve para sites de staging e intranet."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["verificar cabeçalhos de segurança", "csp evaluator", "verificar content security policy", "cabeçalhos de segurança http", "analisador csp", "verificar hsts", "analisar cabeçalhos de resposta", "x-frame-options"]
tags: ["segurança", "csp", "http", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/security-headers/"
tool_title: "Analisador de cabeçalhos de segurança e CSP"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Copie os cabeçalhos de resposta da página que quer verificar: rode `curl -sI https://example.com` num terminal ou abra DevTools → **Rede**, recarregue, selecione a requisição da página e copie os **Cabeçalhos de resposta**."
  - "Cole em **Cabeçalhos de resposta ou CSP**. Você também pode colar só uma política (`default-src 'self'; …`) ou uma tag `<meta http-equiv=\"Content-Security-Policy\">`."
  - "O resultado aparece ao colar: uma nota e depois todos os resultados ordenados de **Grave** a **OK**, cada um com o cabeçalho envolvido e o que mudar."
  - "Em **Content-Security-Policy**, cada diretiva aparece com suas origens; as arriscadas ficam em vermelho ou âmbar, as seguras em verde."
  - "Clique em **Copiar relatório** para colar os resultados num chamado ou pull request. Teste **Exemplo fraco** e **Exemplo forte** para ver a diferença."
faq:
  - q: "A ferramenta se conecta ao meu site?"
    a: "Não. Ela não baixa nenhuma URL: só analisa o texto que você cola, no navegador. Assim seu servidor não aparece em logs de terceiros e você pode verificar sites não públicos, como staging, intranet ou localhost."
  - q: "Por que colar os cabeçalhos em vez de digitar uma URL?"
    a: "As regras de CORS do navegador impedem uma página web de ler outra URL, a menos que um servidor faça isso por você — e esse servidor veria todos os sites que você testa. Colar a saída do `curl -sI` é igualmente rápido e mantém tudo local."
  - q: "O que torna uma Content-Security-Policy fraca?"
    a: "Os problemas comuns são `'unsafe-inline'` em script-src (deixa rodar scripts inline injetados), origens de esquema como `https:` ou `data:` e o curinga `*` (scripts de quase qualquer lugar), CDNs permitidas que hospedam endpoints JSONP ou o antigo AngularJS, e a falta de object-src ou base-uri. Uma pesquisa do Google mostrou que a maioria das políticas baseadas em lista de hosts pode ser contornada; nonces com 'strict-dynamic' evitam isso."
  - q: "O que é uma CSP estrita?"
    a: "Uma política que permite scripts por um nonce aleatório (ou um hash) em vez de por host, mais `'strict-dynamic'` para que os scripts confiáveis possam carregar outros. É a abordagem recomendada pelo Google e pela OWASP contra XSS. O exemplo em \"Como funciona\" é um bom ponto de partida: publique primeiro como Content-Security-Policy-Report-Only e corrija o que for relatado."
  - q: "Como a nota é calculada?"
    a: "Começa em 100 e perde 20 pontos por resultado grave, 10 por médio e 4 por leve; informações e verificações aprovadas não custam nada. A+ exige nenhum resultado grave ou médio. A nota é um resumo rápido, não uma certificação: leia os resultados, porque o impacto depende do seu site."
  - q: "Ainda preciso de X-Frame-Options e X-XSS-Protection?"
    a: "Nos navegadores atuais, o frame-ancestors da CSP substitui o X-Frame-Options, mas enviar os dois não faz mal e cobre os antigos, então a ferramenta aceita qualquer um. X-XSS-Protection está obsoleto: os navegadores removeram o filtro que ele controlava, então a ferramenta recomenda removê-lo ou enviar 0."
  - q: "Quais atributos de cookie são verificados?"
    a: "Secure (enviado só por HTTPS), HttpOnly (escondido do JavaScript), SameSite (limita o envio entre sites, uma defesa contra CSRF) e as regras dos prefixos __Host- e __Secure-. Um cookie com SameSite=None mas sem Secure é rejeitado pelos navegadores e marcado como grave."
---

## Como funciona

### Colar, separar, verificar

O texto colado é dividido em linhas de cabeçalho. Linhas de status como `HTTP/2 200`, pseudocabeçalhos do HTTP/2 e linhas quebradas são tratados; se você colar uma cadeia de redirecionamentos, só a última resposta é analisada. Cabeçalhos repetidos como `Set-Cookie` são verificados um a um. Se o texto começar com uma diretiva CSP, ou for uma tag `<meta>` de CSP, só a política é analisada.

Depois, cada cabeçalho é comparado com o comportamento atual dos navegadores e com as recomendações da OWASP, do MDN e da especificação CSP. Cada resultado tem uma gravidade, o cabeçalho envolvido e uma correção concreta.

### As verificações da CSP

A política é separada em diretivas e origens. O analisador descobre qual diretiva realmente controla os scripts (`script-src`, ou `default-src` quando ela falta) e os plugins (`object-src` herda de `default-src`; `base-uri` e `form-action` não herdam nada). Ele aponta `'unsafe-inline'` e `'unsafe-eval'`, curingas, origens de esquema, hosts por HTTP, hosts permitidos conhecidos por servir JSONP ou versões arbitrárias de bibliotecas, nonces curtos, `'strict-dynamic'` sem nonce e erros de sintaxe que os navegadores ignoram em silêncio: palavras-chave sem aspas (`self` em vez de `'self'`), ponto e vírgula faltando, diretivas duplicadas, desconhecidas e obsoletas.

### Uma política estrita para começar

```text
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'self'
```

Gere um nonce aleatório novo (pelo menos 128 bits) a cada resposta e adicione `nonce="{RANDOM}"` a cada tag `<script>`. Envie primeiro como `Content-Security-Policy-Report-Only`, corrija o que quebrar e depois aplique.

## Casos de uso

- **Antes de um lançamento.** Verifique os cabeçalhos de um site de staging, que scanners online não alcançam.
- **Pull requests e auditorias.** Cole os cabeçalhos antes e depois de uma mudança e copie o relatório na revisão.
- **Aprender CSP.** Entenda, diretiva por diretiva, por que cada origem de uma política é ou não um risco.
- **Anotações de pentest e bug bounty.** Transforme uma resposta capturada numa lista de problemas de cabeçalho com correções.
- **Revisão de cookies.** Confira se os cookies de sessão continuam Secure, HttpOnly e SameSite depois de atualizar o framework.
