---
title: "Verificar SPF, DKIM e DMARC de um domínio"
description: "Verifique os registros SPF, DKIM e DMARC de um domínio, conte as consultas SPF contra o limite de 10, confira chaves DKIM e BIMI e receba correções."
intro: "Digite um domínio para avaliar sua **autenticação de e-mail**. A ferramenta lê o registro **SPF** e conta as consultas DNS **por todos os include** contra o limite de 10, lê a **política DMARC**, a porcentagem, os endereços de relatório e o alinhamento, mede o **tamanho das chaves DKIM** e confere **MX** e **BIMI**. Cada problema vem com um **registro de exemplo** para corrigi-lo. As consultas DNS vão para o resolvedor DNS-over-HTTPS da Cloudflare, só quando você clica em Verificar."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["verificar spf", "verificar dmarc", "verificar dkim", "teste spf dkim dmarc", "verificar registro spf", "exemplo registro dmarc", "spf muitas consultas dns", "tamanho chave dkim", "política dmarc reject", "registro bimi"]
tags: ["security", "email", "dns", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/spf-dmarc-checker/"
tool_title: "Verificador de SPF, DKIM e DMARC"
tool_height: 1150
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Digite um **domínio** (ou cole um endereço de e-mail; só a parte depois do @ é usada)."
  - "Opcional: digite seus **seletores DKIM**, separados por vírgulas. Sem eles, a ferramenta testa nomes de seletor comuns."
  - "Clique em **Verificar**. É o único momento em que consultas DNS são enviadas."
  - "Leia a **nota** e cada seção: SPF com a contagem de consultas e a árvore de include, tags DMARC, chaves DKIM, MX e BIMI."
  - "Em **Correções sugeridas**, copie os registros de exemplo, substitua as partes entre sinais de menor e maior e confirme com seu provedor de e-mail antes de publicá-los."
faq:
  - q: "O que é enviado, e para quem?"
    a: "Quando você clica em Verificar, seu navegador envia consultas DNS do domínio (os registros TXT de SPF, _dmarc, seletores DKIM e BIMI, e os registros MX) ao resolvedor público DNS-over-HTTPS da Cloudflare, cloudflare-dns.com. Como qualquer requisição web, isso revela à Cloudflare seu endereço IP e o user-agent do navegador. Nada é enviado a este site, e nada sai antes de você clicar no botão."
  - q: "Por que o SPF tem limite de 10 consultas?"
    a: "O padrão SPF (RFC 7208) limita a 10 por verificação os mecanismos que precisam de consulta DNS — include, a, mx, ptr, exists e o modificador redirect —, contados por todos os include aninhados. Destinatários que passam do limite param com erro permanente, e o SPF falha para todo o seu e-mail, não só para os remetentes a mais. ip4, ip6 e all não contam."
  - q: "Por que nenhuma chave DKIM é encontrada se meu e-mail é assinado?"
    a: "As chaves DKIM ficam sob um nome de seletor escolhido pelo provedor (seletor._domainkey.seudominio), e o DNS não permite listá-las. A ferramenta testa só alguns nomes comuns. Encontre seu seletor na tag s= de um cabeçalho DKIM-Signature (o analisador de cabeçalhos de e-mail deste site mostra) e digite-o."
  - q: "p=none é suficiente?"
    a: "É o primeiro passo certo: você recebe relatórios sem afetar a entrega. Mas isso não impede ninguém de falsificar seu domínio. Quando os relatórios mostrarem que seus remetentes legítimos passam, mude para p=quarantine e depois p=reject."
  - q: "~all ou -all?"
    a: "Os dois marcam servidores não listados como não autorizados. Com DMARC em quarantine ou reject, os destinatários seguem o resultado DMARC de qualquer forma, então ~all é uma escolha comum e segura; -all é mais rígido, e alguns destinatários podem recusar a mensagem só por isso, antes de avaliar o DMARC."
  - q: "Os registros de exemplo estão prontos para colar?"
    a: "São pontos de partida criados a partir dos seus registros atuais. As partes entre sinais de menor e maior precisam ser substituídas, e só você ou seu provedor conhecem todos os serviços que enviam pelo seu domínio. Confirme com o provedor e verifique de novo depois que o DNS for atualizado."
---

## Como funciona

### SPF: contar as consultas como os destinatários

A ferramenta busca os registros TXT do domínio e fica com o que começa com `v=spf1`. Depois percorre o registro termo a termo. Cada `include`, `a`, `mx`, `ptr`, `exists` e `redirect` soma uma consulta, e cada `include` também é buscado e percorrido, então provedores aninhados também contam. O total é comparado com o limite de 10 da RFC 7208. A ferramenta também aponta include para domínios sem SPF, mais de duas consultas que não retornam nada, laços de include, o mecanismo desaconselhado `ptr` e o qualificador de `all`.

### DMARC: política, cobertura e relatórios

O registro em `_dmarc.<domínio>` é analisado tag por tag. Um subdomínio sem registro próprio herda o do domínio principal e a política `sp=`, como fazem os destinatários. A nota depende da política (`none`, `quarantine`, `reject`), de `pct`, de haver relatórios agregados (`rua`) e de os endereços de relatório em outro domínio terem publicado o registro de autorização necessário (RFC 7489, seção 7.1).

### DKIM: tamanho da chave lido da própria chave pública

Para cada seletor encontrado, o valor `p=` é decodificado e o tamanho do módulo RSA é lido da chave. Chaves abaixo de 1024 bits não devem ser aceitas pelos destinatários (RFC 8301); o tamanho recomendado é 2048 bits. Chaves vazias aparecem como revogadas, e chaves Ed25519 são reconhecidas.

### MX e BIMI

Os registros MX mostram onde o domínio recebe e-mail; um "null MX" (`0 .`) significa que ele não aceita nenhum. O BIMI (`default._bimi`) é opcional e só funciona com uma política DMARC aplicada a 100%.

## Casos de uso

- **Antes de enviar newsletters** — garanta que SPF, DKIM e DMARC passem para chegar à caixa de entrada.
- **Depois de adicionar um serviço de e-mail** — confira se o novo `include:` não levou o SPF acima de 10 consultas.
- **Proteger um domínio** — passe o DMARC de `p=none` para `p=reject` com segurança e proteja domínios que nunca enviam e-mail.
- **Revisões de segurança** — confira a proteção contra falsificação dos domínios de um fornecedor ou da sua organização.
- **Investigar um e-mail suspeito** — veja o que o domínio do remetente publica e depois leia a mensagem com o [analisador de cabeçalhos de e-mail](../email-header-analyzer/).
