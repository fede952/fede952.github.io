---
title: "Este Link é Seguro? Verificador de Phishing"
description: "Cole um link suspeito e veja os truques de phishing na estrutura dele: IP, logins escondidos com @, domínios punycode, TLDs de risco. Sem precisar abrir."
intro: "O **LinkHazmat** destrincha uma URL *sem visitá-la* e aponta os truques estruturais que os links de phishing usam: hosts com endereço IP, logins escondidos com `@`, domínios clone em punycode, TLDs de risco, marcas em subdomínios e parâmetros de redirecionamento. Depois oferece links diretos para scanners de reputação mais profundos."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["este link é seguro", "verificar link", "verificador de phishing", "link suspeito", "scanner de url", "como saber se um link é seguro", "identificar link de phishing", "testar link"]
tags: ["segurança", "phishing", "scanner-url", "ferramenta"]
app_category: "SecurityApplication"
tool_partial: "link-hazmat"
howto:
  - "Copie o link suspeito *sem abrir*: segure o dedo ou clique com o botão direito e escolha \"Copiar endereço do link\"."
  - "Cole na caixa e clique em **INITIATE SCAN** (ou Enter). Se faltar `http://`, ele é adicionado automaticamente."
  - "Leia o veredito: **LOW RISK**, **SUSPICIOUS** ou **HIGH RISK**, com cada truque encontrado listado em *Tricks detected*."
  - "Confira o protocolo, o domínio real e a extensão (TLD) para onde o link aponta de verdade: o domínio real muitas vezes é bem diferente do que o texto do link sugere."
  - "Para uma segunda opinião, use os botões **VirusTotal**, **Google Transparency** ou **Urlscan.io**, que abrem esses serviços com o link já preenchido."
faq:
  - q: "Como saber se um link é seguro antes de clicar?"
    a: "Olhe o domínio real, a parte logo antes da primeira `/` simples. Em `https://paypal.com.secure-login.xyz/…` o domínio é `secure-login.xyz`, não o PayPal. Desconfie de endereços IP no lugar de nomes, de um `@` no endereço, de extensões estranhas, de muitos hífens e de qualquer página que peça login depois de um e-mail ou SMS."
  - q: "O LinkHazmat visita o link?"
    a: "Não. A URL só é analisada como texto com o parser `URL` do navegador; nada é baixado, então uma página maliciosa não consegue carregar nem executar nada. Um terceiro só vê o link se você clicar em um dos botões de scanners externos."
  - q: "Um link LOW RISK ainda pode ser perigoso?"
    a: "Sim. É uma verificação estrutural: ela pega os truques que fazem um link *parecer* legítimo, não se o site por trás de um domínio de aparência normal é malicioso. Um domínio recém-registrado com estrutura limpa tira nota baixa. Na dúvida, use os scanners de reputação ou abra o site digitando você mesmo o endereço."
  - q: "O que é um ataque de punycode ou homógrafo?"
    a: "Domínios podem ter letras não latinas, guardadas numa forma ASCII que começa com `xn--`. Atacantes registram clones como `аpple.com` com um а cirílico, que aparece quase igual ao original. O LinkHazmat converte o host para a forma ASCII, então qualquer rótulo `xn--` fica exposto e sinalizado."
  - q: "Por que um @ numa URL é suspeito?"
    a: "Tudo o que vem antes de um `@` na parte de autoridade de uma URL é tratado como nome de usuário, não como host. `https://www.bank.com@evil.example/` leva, na verdade, para `evil.example`. Links legítimos quase nunca usam isso, por isso a ferramenta soma dois pontos."
  - q: "Quais TLDs são sinalizados?"
    a: "`.xyz`, `.top`, `.gq`, `.zip`, `.mov`, `.tk`, `.ml`, `.ga`, `.cf`, `.buzz`, `.icu` e `.cam`: extensões baratas ou gratuitas que aparecem de forma desproporcional em denúncias de abuso. Muitos sites honestos as usam, então elas só somam um ponto."
---

## Como funciona

A entrada é analisada com o construtor padrão `URL` do navegador (com `http://` na frente se não houver esquema). Assim se obtêm o protocolo, o nome do host em forma ASCII e a query string exatamente como um navegador interpretaria, o que importa porque o phishing vive da diferença entre como uma URL *parece* e para onde ela *leva*.

Cada verificação soma pontos a uma nota de risco:

| Verificação | O que procura | Pontos |
|---|---|---|
| Sem criptografia | `http:` em vez de `https:` | +1 |
| Host IP | um host como `185.12.4.9` em vez de um domínio | +2 |
| Login escondido | um `@` em qualquer lugar da entrada | +2 |
| TLD de risco | uma de 12 extensões muito abusadas | +1 |
| Domínio longo | nome do host com mais de 50 caracteres | +1 |
| Aninhamento profundo | mais de 4 rótulos, ex. `a.b.c.d.com` | +1 |
| Punycode | um rótulo começando com `xn--` (clone internacionalizado) | +2 |
| Muitos hífens | 3 ou mais hífens no host | +1 |
| Parâmetro de redirecionamento | `redirect=`, `url=`, `goto=`, `next=`, `redir=` ou `link=` na query | +1 |
| Marca no subdomínio | paypal, apple, google, microsoft, amazon, netflix, bank, secure, login, verify ou account à *esquerda* do domínio registrável | +2 |

Nota **0** é *LOW RISK*, **1–2** é *SUSPICIOUS* e **3 ou mais** é *HIGH RISK*. A verificação de marcas só olha os rótulos do subdomínio: `www.paypal.com` passa, enquanto `paypal.com.account-check.xyz` (domínio registrável `account-check.xyz`) é sinalizado. O domínio registrável é aproximado pelos dois últimos rótulos, então sufixos compostos como `.com.br` contam um nível a menos.

Os botões de análise profunda montam links para a busca do VirusTotal, para o status de Safe Browsing do Google e para a busca do urlscan.io, com seu domínio ou URL codificados. Eles só abrem, numa nova aba, quando você clica.

## Casos de uso

- **Checar um link de e-mail ou SMS** que diz ser do seu banco, de uma transportadora ou de um serviço de streaming antes de decidir se vai tocar nele.
- **Suporte e SOC.** Passe a um colega uma leitura estrutural rápida de um link denunciado e depois parta para os scanners de reputação.
- **Treinamento de segurança.** Cole exemplos reais de phishing e mostre quais truques cada um usa.
- **Links de QR code.** Leia um QR code com a câmera sem abrir e cole a URL aqui primeiro.
- **Revisar seus próprios links.** Garanta que links de marketing com parâmetros de rastreamento ou redirecionamento não pareçam phishing para usuários cautelosos.
