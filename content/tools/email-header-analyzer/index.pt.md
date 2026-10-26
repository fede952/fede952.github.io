---
title: "Analisar cabeçalho de e-mail: SPF e DKIM"
description: "Cole os cabeçalhos de um e-mail para rastrear cada servidor, conferir SPF, DKIM e DMARC e detectar remetentes falsos. Grátis, privado e no navegador."
intro: "Cole os **cabeçalhos brutos** de um e-mail suspeito para ver de onde ele veio de verdade. O analisador reconstrói o **caminho servidor por servidor** com o atraso de cada salto, lê os resultados **SPF, DKIM, DMARC e ARC** registrados pelo seu provedor e aponta as **divergências** entre From, Reply-To e Return-Path. Tudo é analisado no seu navegador: os cabeçalhos não são enviados para lugar nenhum."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["analisar cabeçalho de e-mail", "ver cabeçalho do email", "verificar remetente de e-mail", "como saber se um e-mail é falso", "gmail mostrar original cabeçalho", "verificar spf dkim dmarc e-mail", "rastrear origem de e-mail", "detectar e-mail falsificado"]
tags: ["security", "email", "phishing", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/email-header-analyzer/"
tool_title: "Analisador de cabeçalhos de e-mail"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Copie os cabeçalhos brutos do seu programa de e-mail (veja **Como obter os cabeçalhos** abaixo) — ou todo o código-fonte da mensagem; o corpo é ignorado."
  - "Cole-os na caixa. A análise roda ao colar; clique em **Analisar** para repetir."
  - "Leia o **veredito** e os **sinais**, do mais grave ao mais leve. Cada um explica o que significa e quando é inofensivo."
  - "Confira a tabela **Identidade do remetente**: os domínios de From, Reply-To e Return-Path normalmente pertencem à mesma organização."
  - "Siga o **caminho** do primeiro servidor até a sua caixa de entrada. Atrasos longos e servidores inesperados merecem uma segunda olhada."
faq:
  - q: "Meus cabeçalhos são enviados para algum lugar?"
    a: "Não. Os cabeçalhos são analisados pelo JavaScript desta página e a ferramenta não faz requisições de rede. Você pode abrir a página, desconectar da internet e ela continua funcionando."
  - q: "O analisador pode dizer com certeza se um e-mail é phishing?"
    a: "Nenhuma ferramenta pode. Os cabeçalhos mostram como a mensagem viajou e se o domínio do remetente a garantiu. Uma mensagem pode passar em todas as verificações e ainda assim ser golpe, enviada de um domínio parecido que pertence ao golpista: olhe também o domínio do From e os links (a ferramenta Link Hazmat deste site verifica links)."
  - q: "Por que alguns cabeçalhos não são considerados confiáveis?"
    a: "Tudo o que fica abaixo das linhas Received adicionadas pelo seu provedor pode ser escrito por qualquer um no caminho, inclusive o remetente. O analisador confia no cabeçalho Authentication-Results do seu provedor e trata o resto como alegações. Se você colar uma mensagem encaminhada como anexo, analise o original anexado, não a mensagem de encaminhamento."
  - q: "O que significam SPF, DKIM e DMARC?"
    a: "O SPF lista quais servidores podem enviar e-mail por um domínio. O DKIM é uma assinatura criptográfica adicionada pelo domínio remetente. O DMARC passa quando SPF ou DKIM passam para o mesmo domínio exibido no From, e diz aos destinatários o que fazer quando nenhum passa. O ARC registra os resultados originais quando uma lista ou um encaminhamento altera a mensagem."
  - q: "Por que uma newsletter autêntica tem outro Return-Path?"
    a: "Serviços de envio mandam e-mails em nome de empresas e recolhem as devoluções num domínio ou subdomínio próprio. Por isso um Return-Path ou Message-ID de outro domínio é marcado só como leve: ele importa quando vem junto com um DMARC reprovado ou um Reply-To num domínio sem relação."
  - q: "Por que alguns horários voltam no tempo?"
    a: "Cada servidor registra a hora do próprio relógio, e alguns relógios estão errados. O analisador aponta isso como diferença de relógio e mostra o caminho em ordem mesmo assim."
---

## Como obter os cabeçalhos

A maioria dos programas de e-mail esconde os cabeçalhos. Abra a mensagem primeiro e depois:

- **Gmail (web)** — abra a mensagem, clique no botão **⋮ Mais** ao lado de Responder e escolha **Mostrar original**. Clique em **Copiar para a área de transferência**. O app do Gmail no celular não mostra cabeçalhos: use um navegador.
- **Outlook para Windows (clássico)** — clique duas vezes na mensagem para abri-la numa janela própria e vá em **Arquivo → Propriedades**. Os cabeçalhos ficam na caixa **Cabeçalhos de Internet**, embaixo: clique nela, pressione Ctrl+A e Ctrl+C.
- **Novo Outlook e Outlook na web** — abra a mensagem, clique em **… Mais ações → Exibir → Exibir detalhes da mensagem** e copie o texto.
- **Apple Mail (Mac)** — selecione a mensagem e escolha **Visualizar → Mensagem → Todos os Cabeçalhos** (⇧⌘H), ou **Visualizar → Mensagem → Fonte Bruta** (⌥⌘U) para a mensagem inteira. O Mail no iPhone e no iPad não mostra cabeçalhos.
- **Thunderbird** — selecione a mensagem e escolha **Exibir → Código-fonte da mensagem** (Ctrl+U, ⌘U no Mac). Copie tudo o que vem antes da primeira linha em branco, ou simplesmente tudo.

Os nomes dos menus podem variar um pouco conforme a versão. Não encaminhe o e-mail suspeito para você mesmo para ver os cabeçalhos: o encaminhamento cria uma mensagem nova, com cabeçalhos novos.

## Como funciona

### O caminho: as linhas Received são lidas de baixo para cima

Cada servidor que lida com uma mensagem adiciona uma linha **Received** no topo, então a mais antiga fica no fim. O analisador as inverte numa linha do tempo do primeiro servidor até a sua caixa e mostra o tempo entre os saltos. Só são confiáveis as linhas adicionadas pelo seu próprio provedor: um remetente pode escrever linhas Received falsas abaixo delas, e é por isso que o analisador se baseia nos resultados de autenticação e não na origem declarada.

### Autenticação: o que o seu provedor já verificou

Quando uma mensagem chega, o seu provedor verifica **SPF**, **DKIM** e **DMARC** e registra os resultados no cabeçalho **Authentication-Results**. O analisador lê esse cabeçalho e confere também o **alinhamento**: uma assinatura DKIM ou um SPF aprovado só protegem você se forem da mesma organização do endereço From. Ele não consulta o DNS nem verifica assinaturas por conta própria, porque o provedor já fez isso na entrega, com as chaves válidas naquele momento.

### Divergências de identidade

O nome exibido é texto livre, então golpistas costumam colocar nele um endereço confiável (`"ajuda@seubanco.example" <x@random.test>`). O analisador compara os domínios de **From**, **Reply-To**, **Return-Path** e do **Message-ID**, e explica quais diferenças são normais em serviços de envio e quais denunciam um impostor.

## Casos de uso

- **Um e-mail suspeito** — confira se a mensagem do "banco" ou da "transportadora" veio mesmo daquele domínio antes de clicar em qualquer coisa.
- **Suporte e equipes de segurança** — faça a triagem rápida de phishing denunciado e cole a linha do tempo num chamado.
- **Entregabilidade** — descubra por que suas próprias newsletters falham no DMARC ou caem no spam, e qual salto atrasa a entrega.
- **Para aprender** — entenda SPF, DKIM e DMARC com exemplos realistas e depois teste-se com o [quiz de phishing](../phishing-quiz/).
