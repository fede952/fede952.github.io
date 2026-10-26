---
title: "Mensagem criptografada com senha em um link"
description: "Criptografe uma mensagem no navegador com AES-256 e uma frase-senha e compartilhe como link. O texto nunca é enviado: ele existe só dentro do link."
intro: "Escreva uma mensagem, escolha uma frase-senha e receba um **link** que contém a mensagem **criptografada com AES-256-GCM**. Envie o link e a frase-senha **por canais diferentes**; quem recebe abre o link e descriptografa no próprio navegador. Nada é enviado nem armazenado: o texto criptografado viaja dentro do próprio link, na parte depois do `#` que os navegadores nunca mandam para um servidor."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["link mensagem criptografada", "enviar mensagem criptografada", "criptografar texto online", "mensagem protegida por senha", "compartilhar senha com segurança", "enviar nota secreta", "criptografar mensagem com senha", "link mensagem privada"]
tags: ["security", "privacy", "encryption", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/encrypted-message/"
tool_title: "Link de mensagem criptografada"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Escreva a **mensagem**: uma senha do Wi-Fi, o código do portão, uma nota privada curta."
  - "Digite uma **frase-senha** de pelo menos 8 caracteres, ou clique em **Gerar** para uma aleatória."
  - "Clique em **Criar link criptografado** e em **Copiar link**."
  - "Envie o link por um canal (por exemplo, e-mail) e a **frase-senha por outro** (uma ligação, outro app de mensagens). Nunca os dois na mesma mensagem."
  - "Quem recebe abre o link, digita a frase-senha e lê a mensagem no próprio navegador."
faq:
  - q: "Minha mensagem é enviada para algum lugar?"
    a: "Não. A criptografia acontece no seu navegador com a Web Crypto API. A mensagem criptografada vai no link depois do sinal #, e os navegadores não enviam essa parte ao servidor quando o link é aberto. Este site nunca recebe a mensagem, a frase-senha nem o fragmento do link, então não há nada armazenado que possa vazar ou ser apagado."
  - q: "O link se autodestrói depois de lido?"
    a: "Não, e nenhuma ferramenta sem servidor pode prometer isso. O link é a mensagem criptografada, então ele funciona enquanto alguém tiver uma cópia: numa caixa de entrada, num histórico de conversa, num backup. Trate-o como o próprio segredo: quem tiver o link e a frase-senha pode ler. Se você precisa de uma mensagem que desapareça, use um serviço que a guarde num servidor e a apague depois da leitura, aceitando confiar nesse servidor."
  - q: "Quão forte é a criptografia?"
    a: "A mensagem é criptografada com AES-256 no modo GCM, que também detecta qualquer alteração no link. A chave é derivada da sua frase-senha com PBKDF2-HMAC-SHA-256 e 600.000 iterações, com salt e IV aleatórios para cada mensagem. O ponto fraco é a frase-senha: uma curta ou previsível pode ser quebrada por força bruta por quem tiver o link, então use uma longa ou o botão Gerar."
  - q: "E se a frase-senha estiver errada ou o link cortado?"
    a: "A descriptografia falha com uma mensagem clara. A criptografia autenticada não distingue uma frase-senha errada de um link alterado, então confira os dois. Alguns apps cortam links muito longos: a ferramenta avisa acima de uns 2.000 caracteres."
  - q: "Por que enviar a frase-senha separadamente?"
    a: "Porque o link sozinho não serve sem ela. Se os dois forem juntos no mesmo e-mail ou conversa, qualquer pessoa que consiga ler essa conversa, agora ou depois, por exemplo após uma conta ser invadida, também consegue ler a mensagem."
  - q: "Posso ver o que a ferramenta faz?"
    a: "Sim. O código roda no seu navegador e pode ser lido com as ferramentas de desenvolvedor. Na aba Rede você também pode conferir que criar e abrir um link não envia nenhuma requisição com a sua mensagem."
---

## Como funciona

### Criptografia no seu navegador

Ao clicar em **Criar link criptografado**, a página gera um salt aleatório de 16 bytes e um IV aleatório de 12 bytes, deriva da sua frase-senha uma chave de 256 bits com **PBKDF2-HMAC-SHA-256** (600.000 iterações) e criptografa a mensagem com **AES-256-GCM**. O salt, o IV e o texto cifrado com sua tag de autenticação são juntados, codificados em Base64url e colocados depois de `#v1.` no link.

### Por que a mensagem nunca chega a um servidor

A parte de uma URL depois do `#` é o **fragmento**. Os navegadores a mantêm no dispositivo: ela não é enviada na requisição da página nem entra no cabeçalho `Referer`. O link abre uma página mínima deste site, sem anúncios nem estatísticas, que lê o fragmento, o remove da barra de endereços e pede a frase-senha. A descriptografia acontece no dispositivo de quem recebe.

### Contra o que não protege

- **Quem tiver o link e a frase-senha** — é assim que o destinatário lê, e é assim que qualquer outra pessoa poderia ler.
- **Uma frase-senha fraca** — quem tiver o link pode testar frases offline tão rápido quanto o hardware permitir; as 600.000 iterações deixam cada tentativa lenta, não impossível.
- **Um dispositivo comprometido** — um malware no dispositivo de quem envia ou recebe pode ler a mensagem antes da criptografia ou depois da descriptografia.
- **Cópias do link** — caixas de entrada, históricos de conversa e backups guardam o link. Não há como revogá-lo.

## Casos de uso

- **Compartilhar uma senha ou a chave do Wi-Fi** com um colega ou visita sem deixá-la legível no histórico da conversa.
- **Enviar o código do portão ou a senha do alarme** para um entregador ou quem cuida da casa.
- **Passar um código de recuperação ou uma chave de API** para um colega por e-mail, com a frase-senha dita por telefone.
- **Deixar uma nota privada** num lugar público — um chamado, um fórum, um documento compartilhado — que só quem tiver a frase-senha pode ler.
- **Antes de enviar**, confira o quão difícil é adivinhar sua frase-senha com o [PassFort](../pass-fort/).
