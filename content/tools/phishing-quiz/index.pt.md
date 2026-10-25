---
title: "Quiz de phishing: você reconhece o golpe?"
description: "Teste de phishing grátis: 10 e-mails, SMS, páginas de login, QR codes e links realistas. Reconheça o golpe, veja os sinais de alerta e compartilhe sua nota."
intro: "Dez cenários realistas — **e-mails, SMS, páginas de login, QR codes e links** — sorteados de um conjunto de 32. Em cada um, decida: **phishing ou legítimo?** Depois de cada resposta, os sinais de alerta são destacados direto na simulação, com uma explicação de uma linha. Todas as marcas e domínios são fictícios, e nada do que você faz sai do seu navegador."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["quiz de phishing", "teste de phishing", "como reconhecer phishing", "simulação de phishing", "como identificar e-mail falso", "teste de golpe online", "quiz smishing", "treinamento de conscientização em segurança"]
tags: ["segurança", "phishing", "conscientização", "tool"]
app_category: "EducationalApplication"
tool_file: "/tools/phishing-quiz/"
tool_title: "Quiz de phishing"
tool_height: 980
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write; web-share"
share_scores: 10
share_card_title: "Fiz {score}/10 no quiz de phishing"
howto:
  - "Clique em **Começar o quiz**. Você recebe 10 cenários; três ou quatro são legítimos, então \"tudo é phishing\" não funciona."
  - "Leia a linha de contexto e examine a simulação como faria com a real: o endereço do remetente, para onde o link leva de verdade (passe o mouse ou foque o botão), a barra de endereço, o nome do anexo."
  - "Responda **Phishing** ou **Legítimo**. Os sinais de alerta (ou os indícios de uma mensagem autêntica) são numerados na simulação e explicados abaixo."
  - "No final, você recebe uma nota, um nível e os temas para revisar, com links para ferramentas úteis em cada um."
  - "Use **Compartilhar minha nota** para enviar o resultado: o texto compartilhado contém só a nota e um link."
faq:
  - q: "As empresas do quiz são reais?"
    a: "Não. Todas as marcas, pessoas, telefones e domínios são inventados, e todos os endereços web usam domínios reservados para documentação (.example, .test) ou a faixa de IP de documentação 192.0.2.x: nada no quiz aponta para uma organização real."
  - q: "Minha nota ou meus cliques são enviados para algum lugar?"
    a: "Não. O quiz roda inteiramente no seu navegador e não faz requisições de rede. Nada é salvo. Compartilhar é escolha sua: o botão só passa a nota e o endereço do quiz para o menu de compartilhamento do celular, ou os copia."
  - q: "Como as perguntas são escolhidas?"
    a: "Cada rodada sorteia 10 de 32 cenários, com três ou quatro legítimos e pelo menos três tipos diferentes (e-mail, SMS, página de login, QR code, link). Jogando de novo, você recebe outra combinação."
  - q: "O que são smishing e quishing?"
    a: "Smishing é phishing por SMS ou aplicativo de mensagens. Quishing é phishing por QR code: num adesivo, num cartaz ou dentro de um e-mail. O QR code esconde o endereço até você escanear e te leva para o celular, onde não dá para passar o mouse sobre um link antes de abrir."
  - q: "O que faço com uma mensagem de phishing de verdade?"
    a: "Não clique, não responda e não abra anexos. Denuncie — no trabalho para a equipe de TI ou segurança; fora dele, pela opção \"Denunciar phishing\" do seu provedor de e-mail — e depois apague. Se você já digitou uma senha, troque-a na hora no site verdadeiro e ative a autenticação de dois fatores."
  - q: "Posso usar em treinamentos de segurança?"
    a: "Sim, é grátis e não precisa de cadastro. Veja \"Use para treinar sua equipe\" abaixo para um jeito simples de aplicar numa reunião."
---

## Como funciona

Cada cenário é uma simulação construída com elementos de página reais, não uma imagem: dá para ler com leitor de tela e jogar só pelo teclado. Ela vem com uma linha de contexto ("Você está esperando uma entrega…"), porque uma mensagem ser suspeita muitas vezes depende do que você estava fazendo.

Os cenários cobrem os padrões por trás da maior parte do phishing:

- **Remetente e domínios imitadores** — `velorabank-alerts.test` no lugar de `velorabank.example`, o número 1 no lugar do l.
- **Para onde um link leva de verdade** — o texto visível diz uma coisa e o destino outra; um nome conhecido só como subdomínio do domínio de outra pessoa; o truque do `@`.
- **Pressão** — prazos, ameaças de suspensão, segredo, "agora não posso falar".
- **Pedidos que nenhum serviço de verdade faz** — senha do cartão, cartões-presente, taxas para liberar uma encomenda.
- **Anexos e QR codes** — tipos de arquivo disfarçados, QR codes que te levam para o celular.

O conjunto também tem mensagens legítimas, porque desconfiar de tudo tem um custo: alertas de segurança reais, recibos e redefinições de senha que você pediu. Depois da resposta, os elementos que decidem o caso são numerados na simulação.

A página do resultado te dá um nível e lista os temas por trás dos seus erros, com links para ferramentas úteis: o [Link Hazmat](../link-hazmat/) para verificar links suspeitos e o [analisador de cabeçalhos de e-mail](../email-header-analyzer/) para conferir o remetente.

## Use para treinar sua equipe

O quiz funciona bem como um bloco de 15 minutos numa reunião de equipe:

1. **Compartilhe a tela** e abra esta página. Comece o quiz.
2. **Leia cada cenário em voz alta** e dê 30 segundos para a sala. Peça para votarem, levantando a mão ou no chat, antes de alguém clicar.
3. **Responda como a maioria** e depois vejam juntos os sinais de alerta numerados. Pergunte quem tinha notado cada um.
4. **Depois da rodada**, peça para todos jogarem uma vez sozinhos e compartilharem a nota no chat. A mensagem compartilhada traz só a nota e o link.
5. **Feche com o procedimento de denúncia de vocês**: para quem avisar, como, e o que acontece depois.

Cada rodada é diferente, então as mesmas pessoas podem jogar de novo numa próxima sessão. Nada é rastreado: o quiz é um exercício de aprendizado, não uma avaliação individual.

## Casos de uso

- **Conscientização em segurança** para equipes, escolas e famílias, sem contas e sem coleta de dados.
- **Integração de novos colaboradores**: uma introdução rápida e prática às mensagens que eles vão receber.
- **Autoverificação** antes de abrir aquela mensagem do banco ou da transportadora que você não esperava.
- **Ensino** da diferença entre uma mensagem suspeita e uma autêntica, usando as simulações para debate.
